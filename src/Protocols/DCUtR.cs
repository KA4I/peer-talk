using Common.Logging;
using Ipfs;
using ProtoBuf;
using Semver;
using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace PeerTalk.Protocols
{
    /// <summary>
    ///   Direct Connection Upgrade through Relay (DCUtR) protocol.
    ///   Enables hole-punching to establish direct connections between
    ///   NATed peers using a relay as a coordination channel.
    /// </summary>
    /// <remarks>
    ///   Protocol ID: /libp2p/dcutr
    ///   <para>
    ///   See https://github.com/libp2p/specs/blob/master/relay/DCUtR.md
    ///   </para>
    /// </remarks>
    public class DCUtR : IPeerProtocol
    {
        static readonly ILog log = LogManager.GetLogger(typeof(DCUtR));

        /// <inheritdoc />
        public string Name { get; } = "libp2p/dcutr";

        /// <inheritdoc />
        public SemVersion Version { get; } = new SemVersion(1, 0);

        /// <inheritdoc />
        public override string ToString() => $"/{Name}";

        /// <summary>
        ///   The swarm for making connections.
        /// </summary>
        public Swarm Swarm { get; set; }

        /// <inheritdoc />
        public async Task ProcessMessageAsync(PeerConnection connection, Stream stream, CancellationToken cancel = default)
        {
            // We are the responder (B):
            // Step 1: Read CONNECT message from initiator (A)
            var connectMsg = await ProtoBufHelper.ReadMessageAsync<HolePunch>(stream, cancel).ConfigureAwait(false);

            if (connectMsg.type != HolePunch.Type.CONNECT)
            {
                log.Warn("Expected CONNECT message from DCUtR initiator");
                return;
            }

            // Step 2: Send CONNECT back with our addresses
            var localPeer = connection.LocalPeer;
            var response = new HolePunch
            {
                type = HolePunch.Type.CONNECT,
                ObsAddrs = localPeer?.Addresses?
                    .Where(a => !a.ToString().Contains("/p2p-circuit"))
                    .Select(a => a.WithoutPeerId().ToArray())
                    .ToArray() ?? []
            };

            Serializer.SerializeWithLengthPrefix(stream, response, PrefixStyle.Base128);
            await stream.FlushAsync(cancel).ConfigureAwait(false);

            // Step 3: Read SYNC message
            var syncMsg = await ProtoBufHelper.ReadMessageAsync<HolePunch>(stream, cancel).ConfigureAwait(false);

            if (syncMsg.type != HolePunch.Type.SYNC)
            {
                log.Warn("Expected SYNC message from DCUtR initiator");
                return;
            }

            // Step 4: Both sides now attempt direct connections using exchanged addresses
            if (Swarm != null && connectMsg.ObsAddrs != null)
            {
                _ = TryDirectConnectAsync(connectMsg.ObsAddrs, connection.RemotePeer, cancel);
            }
        }

        /// <summary>
        ///   Initiate a DCUtR hole punch to upgrade a relayed connection to direct.
        /// </summary>
        /// <param name="relayConnection">The existing relayed connection.</param>
        /// <param name="cancel">Cancellation token.</param>
        /// <returns>True if a direct connection was established.</returns>
        public async Task<bool> InitiateAsync(PeerConnection relayConnection, CancellationToken cancel = default)
        {
            var localPeer = relayConnection.LocalPeer;
            var remotePeer = relayConnection.RemotePeer;

            try
            {
                var muxer = await relayConnection.MuxerEstablished.Task.ConfigureAwait(false);
                using var substream = await muxer.CreateStreamAsync("dcutr", cancel).ConfigureAwait(false);
                await relayConnection.EstablishProtocolAsync("/multistream/", substream, cancel).ConfigureAwait(false);
                await relayConnection.EstablishProtocolAsync("/libp2p/dcutr", substream, cancel).ConfigureAwait(false);

                // Step 1: Send CONNECT with our observed addresses
                var connectMsg = new HolePunch
                {
                    type = HolePunch.Type.CONNECT,
                    ObsAddrs = localPeer?.Addresses?
                        .Where(a => !a.ToString().Contains("/p2p-circuit"))
                        .Select(a => a.WithoutPeerId().ToArray())
                        .ToArray() ?? []
                };

                Serializer.SerializeWithLengthPrefix(substream, connectMsg, PrefixStyle.Base128);
                await substream.FlushAsync(cancel).ConfigureAwait(false);

                // Step 2: Read CONNECT response from responder
                var response = await ProtoBufHelper.ReadMessageAsync<HolePunch>(substream, cancel).ConfigureAwait(false);

                if (response.type != HolePunch.Type.CONNECT || response.ObsAddrs == null)
                {
                    log.Debug("DCUtR: invalid CONNECT response");
                    return false;
                }

                // Step 3: Send SYNC to coordinate timing
                var syncMsg = new HolePunch
                {
                    type = HolePunch.Type.SYNC,
                };

                Serializer.SerializeWithLengthPrefix(substream, syncMsg, PrefixStyle.Base128);
                await substream.FlushAsync(cancel).ConfigureAwait(false);

                // Step 4: Attempt direct connections to the addresses provided
                return await TryDirectConnectAsync(response.ObsAddrs, remotePeer, cancel).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                log.Debug($"DCUtR initiation failed: {e.Message}");
                return false;
            }
        }

        private async Task<bool> TryDirectConnectAsync(byte[][] addrs, Peer remotePeer, CancellationToken cancel)
        {
            if (Swarm == null || remotePeer == null || addrs == null)
                return false;

            foreach (var addrBytes in addrs)
            {
                try
                {
                    var addr = new MultiAddress(addrBytes);
                    var fullAddr = addr.WithPeerId(remotePeer.Id);

                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancel);
                    cts.CancelAfter(TimeSpan.FromSeconds(10));

                    await Swarm.ConnectAsync(fullAddr, cts.Token).ConfigureAwait(false);
                    log.Debug($"DCUtR: direct connection to {fullAddr} succeeded");
                    return true;
                }
                catch (Exception e)
                {
                    log.Debug($"DCUtR: direct connect failed: {e.Message}");
                }
            }

            return false;
        }

        // --- Protobuf ---

        [ProtoContract]
        internal class HolePunch
        {
            public enum Type
            {
                CONNECT = 100,
                SYNC = 300,
            }

            [ProtoMember(1)]
            public Type type;

            [ProtoMember(2)]
            public byte[][] ObsAddrs;
        }
    }
}
