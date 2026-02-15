using Common.Logging;
using Ipfs;
using PeerTalk.Cryptography;
using PeerTalk.Multiplex;
using PeerTalk.Protocols;
using Semver;
using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.IO;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace PeerTalk.SecureCommunication
{
    /// <summary>
    ///   Creates a secure connection with a peer using libp2p TLS 1.3.
    /// </summary>
    /// <remarks>
    ///   Implements the libp2p TLS handshake spec with a custom X.509 extension
    ///   (OID 1.3.6.1.4.1.53594.1.1) that embeds the peer's libp2p identity key
    ///   and a signature proving ownership.
    ///   See https://github.com/libp2p/specs/blob/master/tls/tls.md
    /// </remarks>
    public class Tls1 : IEncryptionProtocol
    {
        static readonly ILog log = LogManager.GetLogger(typeof(Tls1));

        /// <summary>
        ///   The libp2p TLS extension OID.
        /// </summary>
        public static readonly string Libp2pTlsExtensionOid = "1.3.6.1.4.1.53594.1.1";

        /// <summary>
        ///   The prefix used for signing the TLS public key.
        /// </summary>
        static readonly byte[] SignaturePrefix = System.Text.Encoding.UTF8.GetBytes("libp2p-tls-handshake:");

        /// <inheritdoc />
        public string Name { get; } = "tls";

        /// <inheritdoc />
        public SemVersion Version { get; } = new SemVersion(1, 0);

        /// <inheritdoc />
        public override string ToString() => "/tls/1.0.0";

        /// <inheritdoc />
        public async Task ProcessMessageAsync(PeerConnection connection, Stream stream, CancellationToken cancel = default)
        {
            await EncryptAsync(connection, cancel).ConfigureAwait(false);

            // If early muxer negotiation succeeded on the responder side,
            // set up the muxer directly instead of returning to multistream loop.
            if (connection.IsIncoming && !string.IsNullOrEmpty(connection.NegotiatedMuxer))
            {
                log.Debug($"TLS early muxer negotiation: setting up {connection.NegotiatedMuxer} on responder");
                var muxer = new YamuxMuxer(initiator: false)
                {
                    Channel = connection.Stream,
                    Connection = connection,
                };
                muxer.SubstreamCreated += (s, e) => _ = connection.ReadMessagesAsync(e, CancellationToken.None);
                connection.MuxerEstablished.TrySetResult(muxer);
                await muxer.ProcessRequestsAsync(cancel).ConfigureAwait(false);
            }
        }

        /// <inheritdoc />
        public async Task<Stream> EncryptAsync(PeerConnection connection, CancellationToken cancel = default)
        {
            var stream = connection.Stream;
            bool isInitiator = !connection.IsIncoming;
            connection.RemotePeer ??= new Peer();

            // Generate an ephemeral ECDSA key pair for the TLS certificate
            using var ecdsaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var cert = CreateLibp2pCertificate(ecdsaKey, connection);

            var sslStream = new SslStream(stream, leaveInnerStreamOpen: true,
                (sender, certificate, chain, errors) =>
                    ValidateRemoteCertificate(certificate, connection.RemotePeer));

            // ALPN: offer yamux for early muxer negotiation, "libp2p" as fallback
            var alpnProtocols = new List<SslApplicationProtocol>
            {
                new SslApplicationProtocol("/yamux/1.0.0"),
                new SslApplicationProtocol("libp2p"),
            };

            if (isInitiator)
            {
                var clientOptions = new SslClientAuthenticationOptions
                {
                    TargetHost = "libp2p",
                    ClientCertificates = new X509CertificateCollection { cert },
                    EnabledSslProtocols = SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                    ApplicationProtocols = alpnProtocols,
                };

                await sslStream.AuthenticateAsClientAsync(clientOptions, cancel).ConfigureAwait(false);
            }
            else
            {
                var certContext = SslStreamCertificateContext.Create(cert, additionalCertificates: null);
                var serverOptions = new SslServerAuthenticationOptions
                {
                    ServerCertificateContext = certContext,
                    ClientCertificateRequired = true,
                    EnabledSslProtocols = SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                    ApplicationProtocols = alpnProtocols,
                };

                await sslStream.AuthenticateAsServerAsync(serverOptions, cancel).ConfigureAwait(false);
            }

            // Check for early muxer negotiation via ALPN
            var negotiatedAlpn = sslStream.NegotiatedApplicationProtocol;
            if (negotiatedAlpn == new SslApplicationProtocol("/yamux/1.0.0"))
            {
                connection.NegotiatedMuxer = "/yamux/1.0.0";
            }

            connection.Stream = sslStream;
            connection.SecurityEstablished.TrySetResult(true);
            log.Debug($"TLS 1.3 handshake complete with {connection.RemotePeer.Id}, muxer={connection.NegotiatedMuxer ?? "none"}");
            return sslStream;
        }

        /// <summary>
        ///   Creates a self-signed X.509 certificate with the libp2p identity extension.
        /// </summary>
        X509Certificate2 CreateLibp2pCertificate(ECDsa ecdsaKey, PeerConnection connection)
        {
            var identityKey = connection.LocalPeer.PublicKey != null
                ? Convert.FromBase64String(connection.LocalPeer.PublicKey)
                : Array.Empty<byte>();

            // Create the libp2p extension value:
            // SignedKey { public_key: bytes, signature: bytes }
            // The signature is over "libp2p-tls-handshake:" + ephemeral_tls_public_key_der
            var tlsPubKeyDer = ecdsaKey.ExportSubjectPublicKeyInfo();
            var dataToSign = new byte[SignaturePrefix.Length + tlsPubKeyDer.Length];
            Buffer.BlockCopy(SignaturePrefix, 0, dataToSign, 0, SignaturePrefix.Length);
            Buffer.BlockCopy(tlsPubKeyDer, 0, dataToSign, SignaturePrefix.Length, tlsPubKeyDer.Length);

            var signature = connection.LocalPeerKey?.Sign(dataToSign) ?? Array.Empty<byte>();

            // Encode as ASN.1 DER: SignedKey ::= SEQUENCE { publicKey OCTET STRING, signature OCTET STRING }
            var extensionValue = EncodeSignedKey(identityKey, signature);

            // Build the self-signed certificate
            var req = new CertificateRequest(
                "CN=libp2p",
                ecdsaKey,
                HashAlgorithmName.SHA256);

            // Add the libp2p extension
            req.CertificateExtensions.Add(
                new X509Extension(new Oid(Libp2pTlsExtensionOid), extensionValue, critical: true));

            // Self-sign with 1 year validity
            using var tmpCert = req.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddYears(1));

            // Re-import via PFX so the private key is usable by SChannel on Windows.
            // CreateSelfSigned creates an ephemeral key that SslStream cannot use.
            var pfxBytes = tmpCert.Export(X509ContentType.Pfx);
            return X509CertificateLoader.LoadPkcs12(pfxBytes, null, X509KeyStorageFlags.Exportable);
        }

        /// <summary>
        ///   Validates the remote peer's TLS certificate by extracting the libp2p extension.
        /// </summary>
        bool ValidateRemoteCertificate(X509Certificate certificate, Peer remotePeer)
        {
            if (certificate == null)
                return false;

            try
            {
                var cert2 = new X509Certificate2(certificate);

                // Find the libp2p extension
                foreach (var ext in cert2.Extensions)
                {
                    if (ext.Oid?.Value == Libp2pTlsExtensionOid)
                    {
                        var (identityKey, signature) = DecodeSignedKey(ext.RawData);
                        if (identityKey == null || identityKey.Length == 0)
                            return false;

                        // Derive peer ID
                        var ridAlg = identityKey.Length <= 48 ? "identity" : "sha2-256";
                        var remoteId = MultiHash.ComputeHash(identityKey, ridAlg);

                        if (remotePeer.Id == null)
                        {
                            remotePeer.Id = remoteId;
                        }
                        else if (remoteId != remotePeer.Id)
                        {
                            log.Error($"TLS: expected peer '{remotePeer.Id}', got '{remoteId}'");
                            return false;
                        }

                        remotePeer.PublicKey = Convert.ToBase64String(identityKey);

                        // Verify signature over "libp2p-tls-handshake:" + tls_public_key
                        if (signature != null && signature.Length > 0)
                        {
                            // Use DER-encoded SubjectPublicKeyInfo per libp2p TLS spec
                            using var ecdsaPub = cert2.GetECDsaPublicKey()
                                ?? throw new InvalidDataException("TLS certificate does not contain an ECDSA public key.");
                            var tlsPubKeyDer = ecdsaPub.ExportSubjectPublicKeyInfo();
                            var dataToVerify = new byte[SignaturePrefix.Length + tlsPubKeyDer.Length];
                            Buffer.BlockCopy(SignaturePrefix, 0, dataToVerify, 0, SignaturePrefix.Length);
                            Buffer.BlockCopy(tlsPubKeyDer, 0, dataToVerify, SignaturePrefix.Length, tlsPubKeyDer.Length);

                            var remoteKey = Key.CreatePublicKeyFromIpfs(identityKey);
                            remoteKey.Verify(dataToVerify, signature);
                        }

                        return true;
                    }
                }

                log.Error("TLS: remote certificate missing libp2p extension");
                return false;
            }
            catch (Exception e)
            {
                log.Error("TLS: certificate validation error", e);
                return false;
            }
        }

        /// <summary>
        ///   Encodes a SignedKey as ASN.1 DER per the libp2p TLS spec.
        /// </summary>
        /// <remarks>
        ///   SignedKey ::= SEQUENCE { publicKey OCTET STRING, signature OCTET STRING }
        /// </remarks>
        static byte[] EncodeSignedKey(byte[] publicKey, byte[] signature)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSequence();
            writer.WriteOctetString(publicKey);
            writer.WriteOctetString(signature);
            writer.PopSequence();
            return writer.Encode();
        }

        /// <summary>
        ///   Decodes a SignedKey from ASN.1 DER per the libp2p TLS spec.
        /// </summary>
        static (byte[] publicKey, byte[] signature) DecodeSignedKey(byte[] data)
        {
            var reader = new AsnReader(data, AsnEncodingRules.DER);
            var sequence = reader.ReadSequence();
            var publicKey = sequence.ReadOctetString();
            var signature = sequence.ReadOctetString();
            return (publicKey, signature);
        }
    }
}
