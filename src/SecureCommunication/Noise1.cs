using Common.Logging;
using Ipfs;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using PeerTalk.Cryptography;
using PeerTalk.Protocols;
using ProtoBuf;
using Semver;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace PeerTalk.SecureCommunication
{
    /// <summary>
    ///   Creates a secure connection with a peer using the Noise protocol.
    /// </summary>
    /// <remarks>
    ///   Implements libp2p Noise with XX handshake pattern.
    ///   Protocol ID: /noise
    ///   See https://github.com/libp2p/specs/blob/master/noise/README.md
    /// </remarks>
    public class Noise1 : IEncryptionProtocol
    {
        static readonly ILog log = LogManager.GetLogger(typeof(Noise1));
        static readonly byte[] Prologue = System.Text.Encoding.UTF8.GetBytes("noise-libp2p-static-key:");

        /// <inheritdoc />
        public string Name { get; } = "noise";

        /// <inheritdoc />
        public SemVersion Version { get; } = new SemVersion(0, 0);

        /// <inheritdoc />
        public override string ToString() => "/noise";

        /// <inheritdoc />
        public async Task ProcessMessageAsync(PeerConnection connection, Stream stream, CancellationToken cancel = default)
        {
            await EncryptAsync(connection, cancel).ConfigureAwait(false);

            // If early muxer negotiation succeeded on the responder side,
            // set up the muxer directly instead of returning to multistream loop.
            if (connection.IsIncoming && !string.IsNullOrEmpty(connection.NegotiatedMuxer))
            {
                log.Debug($"Early muxer negotiation: setting up {connection.NegotiatedMuxer} on responder");
                var muxer = new Multiplex.YamuxMuxer(initiator: false)
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
            var localPeer = connection.LocalPeer;
            connection.RemotePeer ??= new Peer();
            var remotePeer = connection.RemotePeer;
            bool isInitiator = !connection.IsIncoming;

            // Generate a Noise static key (X25519) for this session
            var gen = new X25519KeyPairGenerator();
            gen.Init(new X25519KeyGenerationParameters(new SecureRandom()));
            var noiseKeyPair = gen.GenerateKeyPair();
            var noisePrivKey = ((X25519PrivateKeyParameters)noiseKeyPair.Private).GetEncoded();
            var noisePubKey = ((X25519PublicKeyParameters)noiseKeyPair.Public).GetEncoded();

            var handshake = new NoiseHandshake(noisePrivKey, noisePubKey, isInitiator);

            // libp2p-noise prologue is empty per spec
            handshake.MixPrologue(Array.Empty<byte>());

            byte[] remotePayloadBytes;

            if (isInitiator)
            {
                // -> e (message 1)
                var localPayload = CreatePayload(connection, noisePubKey);
                var msg1 = handshake.WriteMessage1(Array.Empty<byte>());
                await WriteNoiseMessage(stream, msg1, cancel).ConfigureAwait(false);

                // <- e, ee, s, es (message 2)
                var msg2 = await ReadNoiseMessage(stream, cancel).ConfigureAwait(false);
                remotePayloadBytes = handshake.ReadMessage2(msg2);

                // -> s, se (message 3)
                var msg3 = handshake.WriteMessage3(localPayload);
                await WriteNoiseMessage(stream, msg3, cancel).ConfigureAwait(false);
            }
            else
            {
                // <- e (message 1)
                var msg1 = await ReadNoiseMessage(stream, cancel).ConfigureAwait(false);
                handshake.ReadMessage1(msg1);

                // -> e, ee, s, es (message 2)
                var localPayload = CreatePayload(connection, noisePubKey);
                var msg2 = handshake.WriteMessage2(localPayload);
                await WriteNoiseMessage(stream, msg2, cancel).ConfigureAwait(false);

                // <- s, se (message 3)
                var msg3 = await ReadNoiseMessage(stream, cancel).ConfigureAwait(false);
                remotePayloadBytes = handshake.ReadMessage3(msg3);
            }

            handshake.Split();

            // Verify remote peer identity from the payload
            var remotePayload = DeserializePayload(remotePayloadBytes);
            VerifyPayload(remotePayload, handshake.RemoteStaticKey, remotePeer);

            // Check for early muxer negotiation
            if (remotePayload.Extensions?.StreamMuxers != null)
            {
                foreach (var localMuxer in new[] { "/yamux/1.0.0" })
                {
                    foreach (var remoteMuxer in remotePayload.Extensions.StreamMuxers)
                    {
                        if (localMuxer == remoteMuxer)
                        {
                            connection.NegotiatedMuxer = localMuxer;
                            goto muxerDone;
                        }
                    }
                }
                muxerDone:;
            }

            // Set up the encrypted transport stream
            var secureStream = new NoiseStream(stream, handshake.SendKey, handshake.RecvKey);
            connection.Stream = secureStream;
            connection.SecurityEstablished.TrySetResult(true);

            log.Debug($"Noise handshake complete with {remotePeer.Id}, muxer={connection.NegotiatedMuxer ?? "none"}");
            return secureStream;
        }

        byte[] CreatePayload(PeerConnection connection, byte[] noiseStaticPubKey)
        {
            var identityKey = connection.LocalPeer.PublicKey != null
                ? Convert.FromBase64String(connection.LocalPeer.PublicKey)
                : Array.Empty<byte>();

            // Per spec: sign "noise-libp2p-static-key:" + noiseStaticPubKey
            byte[] sig = Array.Empty<byte>();
            if (connection.LocalPeerKey != null)
            {
                var dataToSign = new byte[Prologue.Length + noiseStaticPubKey.Length];
                Buffer.BlockCopy(Prologue, 0, dataToSign, 0, Prologue.Length);
                Buffer.BlockCopy(noiseStaticPubKey, 0, dataToSign, Prologue.Length, noiseStaticPubKey.Length);
                sig = connection.LocalPeerKey.Sign(dataToSign);
            }

            var payload = new NoisePayload
            {
                IdentityKey = identityKey,
                IdentitySig = sig,
                Extensions = new NoiseExtensions
                {
                    StreamMuxers = new List<string> { "/yamux/1.0.0" }
                }
            };

            log.Debug($"Noise payload: identityKey={identityKey.Length}b, sig={sig.Length}b");

            using var ms = new MemoryStream();
            Serializer.Serialize(ms, payload);
            return ms.ToArray();
        }

        static NoisePayload DeserializePayload(byte[] data)
        {
            if (data == null || data.Length == 0)
                return new NoisePayload();

            using var ms = new MemoryStream(data);
            return Serializer.Deserialize<NoisePayload>(ms);
        }

        void VerifyPayload(NoisePayload payload, byte[] remoteNoiseStaticKey, Peer remotePeer)
        {
            if (payload.IdentityKey == null || payload.IdentityKey.Length == 0)
                throw new InvalidDataException("Remote peer identity key is missing in Noise payload.");

            // Derive peer ID from the identity key
            var ridAlg = payload.IdentityKey.Length <= 48 ? "identity" : "sha2-256";
            var remoteId = MultiHash.ComputeHash(payload.IdentityKey, ridAlg);

            if (remotePeer.Id == null)
            {
                remotePeer.Id = remoteId;
            }
            else if (remoteId != remotePeer.Id)
            {
                throw new InvalidDataException($"Expected peer '{remotePeer.Id}', got '{remoteId}'");
            }

            remotePeer.PublicKey = Convert.ToBase64String(payload.IdentityKey);

            // Verify signature: "noise-libp2p-static-key:" + remoteNoiseStaticKey
            if (payload.IdentitySig != null && payload.IdentitySig.Length > 0
                && remoteNoiseStaticKey != null && remoteNoiseStaticKey.Length > 0)
            {
                var dataToVerify = new byte[Prologue.Length + remoteNoiseStaticKey.Length];
                Buffer.BlockCopy(Prologue, 0, dataToVerify, 0, Prologue.Length);
                Buffer.BlockCopy(remoteNoiseStaticKey, 0, dataToVerify, Prologue.Length, remoteNoiseStaticKey.Length);

                var remoteKey = Key.CreatePublicKeyFromIpfs(payload.IdentityKey);
                remoteKey.Verify(dataToVerify, payload.IdentitySig);
            }
        }

        static async Task WriteNoiseMessage(Stream stream, byte[] message, CancellationToken cancel)
        {
            // Noise messages are framed with a 2-byte big-endian length prefix
            var lenBuf = new byte[2];
            lenBuf[0] = (byte)(message.Length >> 8);
            lenBuf[1] = (byte)(message.Length);
            await stream.WriteAsync(lenBuf, 0, 2, cancel).ConfigureAwait(false);
            await stream.WriteAsync(message, 0, message.Length, cancel).ConfigureAwait(false);
            await stream.FlushAsync(cancel).ConfigureAwait(false);
        }

        static async Task<byte[]> ReadNoiseMessage(Stream stream, CancellationToken cancel)
        {
            var lenBuf = new byte[2];
            await ReadExactAsync(stream, lenBuf, 0, 2, cancel).ConfigureAwait(false);
            int len = (lenBuf[0] << 8) | lenBuf[1];
            var msg = new byte[len];
            await ReadExactAsync(stream, msg, 0, len, cancel).ConfigureAwait(false);
            return msg;
        }

        static async Task ReadExactAsync(Stream stream, byte[] buffer, int offset, int count, CancellationToken cancel)
        {
            int totalRead = 0;
            while (totalRead < count)
            {
                int n = await stream.ReadAsync(buffer, offset + totalRead, count - totalRead, cancel).ConfigureAwait(false);
                if (n == 0) throw new EndOfStreamException("Noise handshake: unexpected end of stream");
                totalRead += n;
            }
        }

        [ProtoContract]
        internal class NoisePayload
        {
            [ProtoMember(1)]
            public byte[] IdentityKey { get; set; }

            [ProtoMember(2)]
            public byte[] IdentitySig { get; set; }

            [ProtoMember(4)]
            public NoiseExtensions Extensions { get; set; }
        }

        [ProtoContract]
        internal class NoiseExtensions
        {
            [ProtoMember(1)]
            public List<byte[]> WebtransportCerthashes { get; set; }

            [ProtoMember(2)]
            public List<string> StreamMuxers { get; set; } = new List<string>();
        }
    }
}
