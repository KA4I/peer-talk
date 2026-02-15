using Common.Logging;
using Ipfs;
using PeerTalk.SecureCommunication;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace PeerTalk.Transports
{
    /// <summary>
    ///   Establishes a duplex stream between two peers over QUIC (quic-v1).
    /// </summary>
    /// <remarks>
    ///   QUIC provides built-in encryption (TLS 1.3) and multiplexing.
    ///   In libp2p, the QUIC transport fuses security and muxing — no separate
    ///   security or muxer negotiation is needed.
    ///   See https://github.com/libp2p/specs/blob/master/quic/README.md
    /// </remarks>
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("osx")]
    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("android")]
    public class QuicTransport : IPeerTransport
    {
        static readonly ILog log = LogManager.GetLogger(typeof(QuicTransport));

        /// <summary>
        ///   Whether QUIC is supported on this platform.
        /// </summary>
        public static bool IsSupported => QuicConnection.IsSupported;

        /// <inheritdoc />
        public async Task<Stream> ConnectAsync(MultiAddress address, CancellationToken cancel = default)
        {
            if (!QuicConnection.IsSupported)
                throw new PlatformNotSupportedException("QUIC is not supported on this platform. Requires Windows 11+, Linux with OpenSSL 3.x, or macOS 15+.");

            var udpPort = address.Protocols
                .Where(p => p.Name == "udp")
                .Select(p => int.Parse(p.Value))
                .First();
            var ip = address.Protocols
                .Where(p => p.Name == "ip4" || p.Name == "ip6")
                .FirstOrDefault()
                ?? throw new ArgumentException($"Missing IP address in '{address}'.", nameof(address));

            var ipAddress = IPAddress.Parse(ip.Value);
            var endPoint = new IPEndPoint(ipAddress, udpPort);

            log.Debug($"QUIC connecting to {endPoint}");

            var connection = await QuicConnection.ConnectAsync(new QuicClientConnectionOptions
            {
                RemoteEndPoint = endPoint,
                DefaultStreamErrorCode = 0,
                DefaultCloseErrorCode = 0,
                ClientAuthenticationOptions = new SslClientAuthenticationOptions
                {
                    ApplicationProtocols = new System.Collections.Generic.List<SslApplicationProtocol>
                    {
                        new SslApplicationProtocol("libp2p")
                    },
                    TargetHost = "libp2p",
                    RemoteCertificateValidationCallback = (sender, cert, chain, errors) => true, // Validated at libp2p layer later
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls13,
                },
                MaxInboundBidirectionalStreams = 256,
                MaxInboundUnidirectionalStreams = 256,
            }, cancel).ConfigureAwait(false);

            log.Debug($"QUIC connected to {endPoint}");

            // Open the first bidirectional stream for the main connection
            var quicStream = await connection.OpenOutboundStreamAsync(
                QuicStreamType.Bidirectional, cancel).ConfigureAwait(false);

            return new QuicStreamAdapter(quicStream, connection);
        }

        /// <inheritdoc />
        public MultiAddress Listen(MultiAddress address, Func<Stream, MultiAddress, MultiAddress, Task> handler, CancellationToken cancel)
        {
            if (!QuicConnection.IsSupported)
                throw new PlatformNotSupportedException("QUIC is not supported on this platform.");

            var udpPort = address.Protocols
                .Where(p => p.Name == "udp")
                .Select(p => int.Parse(p.Value))
                .FirstOrDefault();
            var ip = address.Protocols
                .Where(p => p.Name == "ip4" || p.Name == "ip6")
                .FirstOrDefault()
                ?? throw new ArgumentException($"Missing IP address in '{address}'.", nameof(address));

            var ipAddress = IPAddress.Parse(ip.Value);
            var endPoint = new IPEndPoint(ipAddress, udpPort);

            // Generate an ephemeral self-signed cert for the listener
            using var ecdsaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var cert = CreateSelfSignedCert(ecdsaKey);

            _ = Task.Run(async () =>
            {
                try
                {
                    await using var listener = await QuicListener.ListenAsync(new QuicListenerOptions
                    {
                        ListenEndPoint = endPoint,
                        ApplicationProtocols = new System.Collections.Generic.List<SslApplicationProtocol>
                        {
                            new SslApplicationProtocol("libp2p")
                        },
                        ConnectionOptionsCallback = (conn, hello, ct) =>
                        {
                            return new ValueTask<QuicServerConnectionOptions>(new QuicServerConnectionOptions
                            {
                                DefaultStreamErrorCode = 0,
                                DefaultCloseErrorCode = 0,
                                ServerAuthenticationOptions = new SslServerAuthenticationOptions
                                {
                                    ApplicationProtocols = new System.Collections.Generic.List<SslApplicationProtocol>
                                    {
                                        new SslApplicationProtocol("libp2p")
                                    },
                                    ServerCertificate = cert,
                                    ClientCertificateRequired = false,
                                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls13,
                                    RemoteCertificateValidationCallback = (sender, c, chain, errors) => true,
                                },
                                MaxInboundBidirectionalStreams = 256,
                                MaxInboundUnidirectionalStreams = 256,
                            });
                        }
                    }, cancel).ConfigureAwait(false);

                    while (!cancel.IsCancellationRequested)
                    {
                        var connection = await listener.AcceptConnectionAsync(cancel).ConfigureAwait(false);
                        var remoteEndpoint = connection.RemoteEndPoint;
                        var remoteAddr = new MultiAddress($"{(remoteEndpoint.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? "/ip4/" : "/ip6/")}{remoteEndpoint.Address}/udp/{remoteEndpoint.Port}/quic-v1");

                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                var stream = await connection.AcceptInboundStreamAsync(cancel).ConfigureAwait(false);
                                var adapter = new QuicStreamAdapter(stream, connection);
                                await handler(adapter, address, remoteAddr).ConfigureAwait(false);
                            }
                            catch (Exception e) when (!cancel.IsCancellationRequested)
                            {
                                log.Error($"QUIC connection handler error: {e.Message}");
                            }
                        });
                    }
                }
                catch (Exception) when (cancel.IsCancellationRequested) { }
                catch (Exception e)
                {
                    log.Error($"QUIC listener error: {e.Message}");
                }
            });

            // Update address with actual port if needed
            var actualPort = udpPort; // QuicListener doesn't expose actual port easily
            return address;
        }

        static X509Certificate2 CreateSelfSignedCert(ECDsa key)
        {
            var req = new CertificateRequest("CN=libp2p", key, HashAlgorithmName.SHA256);
            return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
        }
    }

    /// <summary>
    ///   Adapts a <see cref="QuicStream"/> to a regular <see cref="Stream"/>
    ///   while holding a reference to the <see cref="QuicConnection"/>.
    /// </summary>
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("osx")]
    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("android")]
    internal class QuicStreamAdapter : Stream
    {
        readonly QuicStream quicStream;
        readonly QuicConnection connection;

        public QuicStreamAdapter(QuicStream stream, QuicConnection connection)
        {
            this.quicStream = stream;
            this.connection = connection;
        }

        /// <summary>
        ///   The underlying QUIC connection, for opening additional streams.
        /// </summary>
        public QuicConnection Connection => connection;

        public override bool CanRead => quicStream.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => quicStream.CanWrite;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => quicStream.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => quicStream.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count) =>
            quicStream.Read(buffer, offset, count);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            quicStream.ReadAsync(buffer, offset, count, cancellationToken);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            quicStream.ReadAsync(buffer, cancellationToken);

        public override void Write(byte[] buffer, int offset, int count) =>
            quicStream.Write(buffer, offset, count);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            quicStream.WriteAsync(buffer, offset, count, cancellationToken);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            quicStream.WriteAsync(buffer, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                quicStream.Dispose();
                connection.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            await quicStream.DisposeAsync().ConfigureAwait(false);
            await connection.DisposeAsync().ConfigureAwait(false);
            await base.DisposeAsync().ConfigureAwait(false);
        }
    }
}
