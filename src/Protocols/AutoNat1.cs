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
    ///   AutoNAT V1 protocol — allows peers to determine if they are behind a NAT
    ///   by asking other peers to dial them back.
    /// </summary>
    /// <remarks>
    ///   Protocol ID: /libp2p/autonat/1.0.0
    ///   <para>
    ///   See https://github.com/libp2p/specs/blob/master/autonat/README.md
    ///   </para>
    /// </remarks>
    public class AutoNat1 : IPeerProtocol
    {
        static readonly ILog log = LogManager.GetLogger(typeof(AutoNat1));

        /// <inheritdoc />
        public string Name { get; } = "libp2p/autonat";

        /// <inheritdoc />
        public SemVersion Version { get; } = new SemVersion(1, 0);

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

        /// <inheritdoc />
        public async Task ProcessMessageAsync(PeerConnection connection, Stream stream, CancellationToken cancel = default)
        {
            // We received a DIAL request from a remote peer — they want us to dial them back.
            var msg = await ProtoBufHelper.ReadMessageAsync<AutoNatMessage>(stream, cancel).ConfigureAwait(false);

            if (msg.type != AutoNatMessage.MessageType.DIAL || msg.dial?.peer == null)
            {
                log.Warn("Invalid AutoNAT message received");
                return;
            }

            // Rate limit check
            ResetCountersIfNeeded();
            if (globalCount >= GlobalLimit)
            {
                await SendResponseAsync(stream, ResponseStatus.E_DIAL_REFUSED, "rate limit exceeded", null, cancel);
                return;
            }

            var remotePeerId = new MultiHash(msg.dial.peer.id);
            if (peerCounts.TryGetValue(remotePeerId, out int peerCount) && peerCount >= PeerLimit)
            {
                await SendResponseAsync(stream, ResponseStatus.E_DIAL_REFUSED, "per-peer rate limit exceeded", null, cancel);
                return;
            }

            globalCount++;
            peerCounts[remotePeerId] = peerCount + 1;

            // Try to dial back on each address provided
            if (msg.dial.peer.addrs == null || msg.dial.peer.addrs.Length == 0)
            {
                await SendResponseAsync(stream, ResponseStatus.E_BAD_REQUEST, "no addresses provided", null, cancel);
                return;
            }

            foreach (var addrBytes in msg.dial.peer.addrs)
            {
                MultiAddress addr;
                try
                {
                    addr = new MultiAddress(addrBytes);
                }
                catch
                {
                    continue;
                }

                // Don't dial back on relay or non-public addresses
                if (addr.ToString().Contains("/p2p-circuit"))
                    continue;

                var fullAddr = addr.WithPeerId(remotePeerId);

                try
                {
                    if (Swarm != null)
                    {
                        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancel);
                        cts.CancelAfter(TimeSpan.FromSeconds(15));
                        var conn = await Swarm.ConnectAsync(fullAddr, cts.Token).ConfigureAwait(false);
                        await SendResponseAsync(stream, ResponseStatus.OK, null, addrBytes, cancel);
                        return;
                    }
                }
                catch (Exception e)
                {
                    log.Debug($"AutoNAT dial-back to {fullAddr} failed: {e.Message}");
                }
            }

            await SendResponseAsync(stream, ResponseStatus.E_DIAL_ERROR, "all dial attempts failed", null, cancel);
        }

        /// <summary>
        ///   Ask a remote peer to dial us back in order to determine if we are publicly reachable.
        /// </summary>
        /// <param name="connection">The connection to the remote peer.</param>
        /// <param name="cancel">Cancellation token.</param>
        /// <returns>The observed address if reachable, null otherwise.</returns>
        public async Task<MultiAddress> RequestDialBackAsync(PeerConnection connection, CancellationToken cancel = default)
        {
            var localPeer = connection.LocalPeer;
            if (localPeer?.Addresses == null || !localPeer.Addresses.Any())
                return null;

            var muxer = await connection.MuxerEstablished.Task.ConfigureAwait(false);
            using var substream = await muxer.CreateStreamAsync("autonat", cancel).ConfigureAwait(false);
            await connection.EstablishProtocolAsync("/multistream/", substream, cancel).ConfigureAwait(false);
            await connection.EstablishProtocolAsync("/libp2p/autonat/", substream, cancel).ConfigureAwait(false);

            // Send DIAL request
            var msg = new AutoNatMessage
            {
                type = AutoNatMessage.MessageType.DIAL,
                dial = new Dial
                {
                    peer = new PeerInfo
                    {
                        id = localPeer.Id.ToArray(),
                        addrs = localPeer.Addresses
                            .Where(a => !a.ToString().Contains("/p2p-circuit"))
                            .Select(a => a.WithoutPeerId().ToArray())
                            .ToArray()
                    }
                }
            };

            Serializer.SerializeWithLengthPrefix(substream, msg, PrefixStyle.Base128);
            await substream.FlushAsync(cancel).ConfigureAwait(false);

            // Read response
            var response = await ProtoBufHelper.ReadMessageAsync<AutoNatMessage>(substream, cancel).ConfigureAwait(false);

            if (response.type != AutoNatMessage.MessageType.DIAL_RESPONSE || response.dialResponse == null)
                return null;

            if (response.dialResponse.status == ResponseStatus.OK && response.dialResponse.addr != null)
            {
                Reachability = NatStatus.Public;
                return new MultiAddress(response.dialResponse.addr);
            }

            Reachability = NatStatus.Private;
            if (!string.IsNullOrEmpty(response.dialResponse.statusText))
                log.Debug($"AutoNAT: peer says {response.dialResponse.statusText}");

            return null;
        }

        private async Task SendResponseAsync(Stream stream, ResponseStatus status, string statusText, byte[] addr, CancellationToken cancel)
        {
            var msg = new AutoNatMessage
            {
                type = AutoNatMessage.MessageType.DIAL_RESPONSE,
                dialResponse = new DialResponse
                {
                    status = status,
                    statusText = statusText,
                    addr = addr
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
        internal class AutoNatMessage
        {
            public enum MessageType
            {
                DIAL = 0,
                DIAL_RESPONSE = 1,
            }

            [ProtoMember(1)]
            public MessageType type;

            [ProtoMember(2)]
            public Dial dial;

            [ProtoMember(3)]
            public DialResponse dialResponse;
        }

        internal enum ResponseStatus
        {
            OK = 0,
            E_DIAL_ERROR = 100,
            E_DIAL_REFUSED = 101,
            E_BAD_REQUEST = 200,
            E_INTERNAL_ERROR = 300,
        }

        [ProtoContract]
        internal class PeerInfo
        {
            [ProtoMember(1)]
            public byte[] id;

            [ProtoMember(2)]
            public byte[][] addrs;
        }

        [ProtoContract]
        internal class Dial
        {
            [ProtoMember(1)]
            public PeerInfo peer;
        }

        [ProtoContract]
        internal class DialResponse
        {
            [ProtoMember(1)]
            public ResponseStatus status;

            [ProtoMember(2)]
            public string statusText;

            [ProtoMember(3)]
            public byte[] addr;
        }
    }

    /// <summary>
    ///   NAT reachability status.
    /// </summary>
    public enum NatStatus
    {
        /// <summary>Reachability not yet determined.</summary>
        Unknown = 0,
        /// <summary>Publicly reachable from the internet.</summary>
        Public = 1,
        /// <summary>Behind a NAT; not publicly reachable.</summary>
        Private = 2,
    }
}
