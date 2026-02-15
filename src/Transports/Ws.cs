using Common.Logging;
using Ipfs;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.WebSockets;
using System.Threading;
using System.Threading.Tasks;

namespace PeerTalk.Transports
{
    /// <summary>
    ///   Establishes a duplex stream between two peers over WebSocket.
    /// </summary>
    /// <remarks>
    ///   WebSocket transport enables browser-to-node connectivity.
    ///   Multiaddr format: /ip4/x.x.x.x/tcp/port/ws
    /// </remarks>
    public class Ws : IPeerTransport
    {
        static readonly ILog log = LogManager.GetLogger(typeof(Ws));

        /// <inheritdoc />
        public async Task<Stream> ConnectAsync(MultiAddress address, CancellationToken cancel = default)
        {
            var tcpPort = address.Protocols
                .Where(p => p.Name == "tcp")
                .Select(p => int.Parse(p.Value))
                .First();
            var ip = address.Protocols
                .Where(p => p.Name == "ip4" || p.Name == "ip6")
                .FirstOrDefault()
                ?? throw new ArgumentException($"Missing IP address in '{address}'.", nameof(address));

            var scheme = address.Protocols.Any(p => p.Name == "wss" || p.Name == "tls") ? "wss" : "ws";
            var uri = new Uri($"{scheme}://{ip.Value}:{tcpPort}/");

            log.Debug($"WebSocket connecting to {uri}");

            var ws = new ClientWebSocket();
            ws.Options.AddSubProtocol("libp2p");
            await ws.ConnectAsync(uri, cancel).ConfigureAwait(false);

            log.Debug($"WebSocket connected to {uri}");

            return new WebSocketStream(ws);
        }

        /// <inheritdoc />
        public MultiAddress Listen(MultiAddress address, Func<Stream, MultiAddress, MultiAddress, Task> handler, CancellationToken cancel)
        {
            // On WASM/Browser there are no raw sockets, so HttpListener cannot work.
            if (OperatingSystem.IsBrowser())
            {
                throw new PlatformNotSupportedException(
                    "WebSocket server listening is not supported in browser environments. Use ConnectAsync instead.");
            }

            var tcpPort = address.Protocols
                .Where(p => p.Name == "tcp")
                .Select(p => int.Parse(p.Value))
                .FirstOrDefault();
            var ip = address.Protocols
                .Where(p => p.Name == "ip4" || p.Name == "ip6")
                .FirstOrDefault()
                ?? throw new ArgumentException($"Missing IP address in '{address}'.", nameof(address));

            var prefix = $"http://{ip.Value}:{tcpPort}/";
            var httpListener = new HttpListener();
            httpListener.Prefixes.Add(prefix);

            try
            {
                httpListener.Start();
            }
            catch (Exception e)
            {
                httpListener.Close();
                throw new Exception($"WebSocket listen failed on {prefix}", e);
            }

            _ = Task.Run(async () =>
            {
                try
                {
                    while (!cancel.IsCancellationRequested)
                    {
                        var context = await httpListener.GetContextAsync().ConfigureAwait(false);
                        if (!context.Request.IsWebSocketRequest)
                        {
                            context.Response.StatusCode = 400;
                            context.Response.Close();
                            continue;
                        }

                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                var wsContext = await context.AcceptWebSocketAsync("libp2p").ConfigureAwait(false);
                                var remoteEnd = context.Request.RemoteEndPoint;
                                var remoteAddr = new MultiAddress(
                                    $"{(remoteEnd.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? "/ip4/" : "/ip6/")}{remoteEnd.Address}/tcp/{remoteEnd.Port}/ws");

                                var stream = new WebSocketStream(wsContext.WebSocket);
                                await handler(stream, address, remoteAddr).ConfigureAwait(false);
                            }
                            catch (Exception e) when (!cancel.IsCancellationRequested)
                            {
                                log.Error($"WebSocket handler error: {e.Message}");
                            }
                        });
                    }
                }
                catch (Exception) when (cancel.IsCancellationRequested) { }
                catch (Exception e)
                {
                    log.Error($"WebSocket listener error: {e.Message}");
                }
                finally
                {
                    httpListener.Close();
                }
            });

            return address;
        }
    }

    /// <summary>
    ///   Adapts a <see cref="WebSocket"/> to a bidirectional <see cref="Stream"/>.
    /// </summary>
    internal class WebSocketStream : Stream
    {
        readonly WebSocket webSocket;
        readonly byte[] recvBuffer = new byte[65536];
        int recvOffset;
        int recvCount;

        public WebSocketStream(WebSocket webSocket)
        {
            this.webSocket = webSocket;
        }

        public override bool CanRead => webSocket.State == WebSocketState.Open;
        public override bool CanSeek => false;
        public override bool CanWrite => webSocket.State == WebSocketState.Open;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count)
        {
            return ReadAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (recvCount > 0)
            {
                int toCopy = Math.Min(count, recvCount);
                Buffer.BlockCopy(recvBuffer, recvOffset, buffer, offset, toCopy);
                recvOffset += toCopy;
                recvCount -= toCopy;
                return toCopy;
            }

            var result = await webSocket.ReceiveAsync(
                new ArraySegment<byte>(recvBuffer, 0, recvBuffer.Length),
                cancellationToken).ConfigureAwait(false);

            if (result.MessageType == WebSocketMessageType.Close)
                return 0;

            int n = Math.Min(count, result.Count);
            Buffer.BlockCopy(recvBuffer, 0, buffer, offset, n);
            if (result.Count > n)
            {
                recvOffset = n;
                recvCount = result.Count - n;
            }
            return n;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            WriteAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
        }

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            await webSocket.SendAsync(
                new ArraySegment<byte>(buffer, offset, count),
                WebSocketMessageType.Binary,
                endOfMessage: true,
                cancellationToken).ConfigureAwait(false);
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                try
                {
                    if (webSocket.State == WebSocketState.Open)
                    {
                        webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "done", CancellationToken.None)
                            .GetAwaiter().GetResult();
                    }
                }
                catch { }
                webSocket.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
