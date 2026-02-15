using Common.Logging;
using Ipfs;
using ProtoBuf;
using Semver;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace PeerTalk.Protocols
{
    /// <summary>
    ///   AutoNAT V2 protocol — improved NAT detection with nonce-based verification
    ///   and single-address dial-back requests.
    /// </summary>
    /// <remarks>
    ///   Protocol ID: /libp2p/autonat/2.0.0
    ///   <para>
    ///   AutoNAT v2 improves upon v1 by requiring the requesting peer to specify
    ///   exactly ONE address to be tested, and the server dials back with a nonce
    ///   that the requester must verify. This prevents amplification attacks and
    ///   provides more reliable NAT detection.
    ///   </para>
    ///   <para>
    ///   See https://github.com/libp2p/specs/blob/master/autonat/autonat-v2.md
    ///   </para>
    /// </remarks>
    public class AutoNat2 : IPeerProtocol
    {
        static readonly ILog log = LogManager.GetLogger(typeof(AutoNat2));

        /// <inheritdoc />
        public string Name { get; } = "libp2p/autonat";

        /// <inheritdoc />
        public SemVersion Version { get; } = new SemVersion(2, 0);

        /// <inheritdoc />
        public override string ToString() => $"/{Name}/{Version}";

        /// <summary>
        ///   The swarm that manages peer connections.
        /// </summary>
        public Swarm Swarm { get; set; }

        /// <summary>
        ///   The current NAT reachability status.
        /// </summary>
        public NatStatus Reachability { get; private set; } = NatStatus.Unknown;

        /// <summary>
        ///   Rate limiting: max dial-back requests per minute.
        /// </summary>
        public int GlobalLimit { get; set; } = 30;

        /// <summary>
        ///   Rate limiting: max dial-back requests per peer per minute.
        /// </summary>
        public int PeerLimit { get; set; } = 3;

        private int globalCount;
        private readonly Dictionary<MultiHash, int> peerCounts = new();
        private DateTime lastReset = DateTime.UtcNow;
        private static readonly Random rng = new();

        /// <inheritdoc />
        public async Task ProcessMessageAsync(PeerConnection connection, Stream stream, CancellationToken cancel = default)
        {
            var msg = await ProtoBufHelper.ReadMessageAsync<AutoNat2Message>(stream, cancel).ConfigureAwait(false);

            if (msg.type != AutoNat2Message.MessageType.DIAL_REQUEST || msg.dialRequest == null)
            {
                log.Warn("Invalid AutoNAT v2 message received");
                return;
            }

            // Rate limit check
            ResetCountersIfNeeded();
            if (globalCount >= GlobalLimit)
            {
                await SendDialResponseAsync(stream, DialResponseStatus.E_REQUEST_REJECTED, 0, cancel);
                return;
            }

            var remotePeerId = connection.RemotePeer?.Id;
            if (!peerCounts.TryGetValue(remotePeerId!, out int peerCount))
                peerCount = 0;
            if (remotePeerId != null && peerCount >= PeerLimit)
            {
                await SendDialResponseAsync(stream, DialResponseStatus.E_REQUEST_REJECTED, 0, cancel);
                return;
            }

            globalCount++;
            if (remotePeerId != null)
                peerCounts[remotePeerId] = peerCount + 1;

            // v2: Exactly one address is sent and the server validates with nonce
            if (msg.dialRequest.addr == null || msg.dialRequest.addr.Length == 0)
            {
                await SendDialResponseAsync(stream, DialResponseStatus.E_BAD_REQUEST, 0, cancel);
                return;
            }

            // Generate a nonce for verification
            ulong nonce = (ulong)(rng.NextInt64() & 0x7FFFFFFFFFFFFFFFL);

            MultiAddress addr;
            try
            {
                addr = new MultiAddress(msg.dialRequest.addr);
            }
            catch
            {
                await SendDialResponseAsync(stream, DialResponseStatus.E_BAD_REQUEST, 0, cancel);
                return;
            }

            // Don't dial relay addresses
            if (addr.ToString().Contains("/p2p-circuit"))
            {
                await SendDialResponseAsync(stream, DialResponseStatus.E_BAD_REQUEST, 0, cancel);
                return;
            }

            // Attempt the dial-back
            try
            {
                if (Swarm != null)
                {
                    var fullAddr = remotePeerId != null ? addr.WithPeerId(remotePeerId) : addr;
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancel);
                    cts.CancelAfter(TimeSpan.FromSeconds(15));

                    var conn = await Swarm.ConnectAsync(fullAddr, cts.Token).ConfigureAwait(false);

                    // Send the nonce over the new connection for verification
                    var muxer = await conn.MuxerEstablished.Task.ConfigureAwait(false);
                    using var substream = await muxer.CreateStreamAsync("autonat-verify", cts.Token).ConfigureAwait(false);
                    await conn.EstablishProtocolAsync("/multistream/", substream, cts.Token).ConfigureAwait(false);
                    await conn.EstablishProtocolAsync("/libp2p/autonat/", substream, cts.Token).ConfigureAwait(false);

                    var dialBack = new AutoNat2Message
                    {
                        type = AutoNat2Message.MessageType.DIAL_BACK,
                        dialBack = new DialBack { nonce = nonce }
                    };
                    Serializer.SerializeWithLengthPrefix(substream, dialBack, PrefixStyle.Base128);
                    await substream.FlushAsync(cts.Token).ConfigureAwait(false);

                    await SendDialResponseAsync(stream, DialResponseStatus.OK, nonce, cancel);
                    return;
                }
            }
            catch (Exception e)
            {
                log.Debug($"AutoNAT v2 dial-back to {addr} failed: {e.Message}");
            }

            await SendDialResponseAsync(stream, DialResponseStatus.E_DIAL_ERROR, 0, cancel);
        }

        /// <summary>
        ///   Request an AutoNAT v2 dial-back from a remote peer for a specific address.
        /// </summary>
        public async Task<NatStatus> RequestDialBackAsync(PeerConnection connection, MultiAddress addressToTest, CancellationToken cancel = default)
        {
            var muxer = await connection.MuxerEstablished.Task.ConfigureAwait(false);
            using var substream = await muxer.CreateStreamAsync("autonat2", cancel).ConfigureAwait(false);
            await connection.EstablishProtocolAsync("/multistream/", substream, cancel).ConfigureAwait(false);
            await connection.EstablishProtocolAsync("/libp2p/autonat/", substream, cancel).ConfigureAwait(false);

            // Generate our nonce
            ulong nonce = (ulong)(rng.NextInt64() & 0x7FFFFFFFFFFFFFFFL);

            var msg = new AutoNat2Message
            {
                type = AutoNat2Message.MessageType.DIAL_REQUEST,
                dialRequest = new DialRequest
                {
                    addr = addressToTest.WithoutPeerId().ToArray(),
                    nonce = nonce
                }
            };

            Serializer.SerializeWithLengthPrefix(substream, msg, PrefixStyle.Base128);
            await substream.FlushAsync(cancel).ConfigureAwait(false);

            // Read response
            var response = await ProtoBufHelper.ReadMessageAsync<AutoNat2Message>(substream, cancel).ConfigureAwait(false);

            if (response.type != AutoNat2Message.MessageType.DIAL_RESPONSE || response.dialResponse == null)
            {
                Reachability = NatStatus.Unknown;
                return Reachability;
            }

            if (response.dialResponse.status == DialResponseStatus.OK && response.dialResponse.nonce == nonce)
            {
                Reachability = NatStatus.Public;
            }
            else
            {
                Reachability = NatStatus.Private;
            }

            return Reachability;
        }

        private async Task SendDialResponseAsync(Stream stream, DialResponseStatus status, ulong nonce, CancellationToken cancel)
        {
            var msg = new AutoNat2Message
            {
                type = AutoNat2Message.MessageType.DIAL_RESPONSE,
                dialResponse = new DialResponse
                {
                    status = status,
                    nonce = nonce
                }
            };
            Serializer.SerializeWithLengthPrefix(stream, msg, PrefixStyle.Base128);
            await stream.FlushAsync(cancel).ConfigureAwait(false);
        }

        private void ResetCountersIfNeeded()
        {
            if ((DateTime.UtcNow - lastReset).TotalMinutes >= 1)
            {
                globalCount = 0;
                peerCounts.Clear();
                lastReset = DateTime.UtcNow;
            }
        }

        // --- Protobuf types ---

        [ProtoContract]
        internal class AutoNat2Message
        {
            public enum MessageType
            {
                DIAL_REQUEST = 0,
                DIAL_RESPONSE = 1,
                DIAL_BACK = 2,
            }

            [ProtoMember(1)]
            public MessageType type;

            [ProtoMember(2)]
            public DialRequest dialRequest;

            [ProtoMember(3)]
            public DialResponse dialResponse;

            [ProtoMember(4)]
            public DialBack dialBack;
        }

        internal enum DialResponseStatus
        {
            OK = 0,
            E_DIAL_ERROR = 100,
            E_REQUEST_REJECTED = 101,
            E_BAD_REQUEST = 200,
            E_INTERNAL_ERROR = 300,
        }

        [ProtoContract]
        internal class DialRequest
        {
            [ProtoMember(1)]
            public byte[] addr;

            [ProtoMember(2)]
            public ulong nonce;
        }

        [ProtoContract]
        internal class DialResponse
        {
            [ProtoMember(1)]
            public DialResponseStatus status;

            [ProtoMember(2)]
            public ulong nonce;
        }

        [ProtoContract]
        internal class DialBack
        {
            [ProtoMember(1)]
            public ulong nonce;
        }
    }
}
