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
    ///   Identify Delta protocol — lightweight incremental updates to peer identity
    ///   (added/removed addresses, protocol changes).
    /// </summary>
    /// <remarks>
    ///   Protocol ID: /p2p/id/delta/1.0.0
    ///   <para>
    ///   Unlike Identify Push which sends the full identity, Delta only
    ///   sends the changes (added/removed addresses and protocols).
    ///   </para>
    ///   <para>
    ///   See https://github.com/libp2p/specs/blob/master/identify/README.md
    ///   </para>
    /// </remarks>
    public class IdentifyDelta1 : IPeerProtocol
    {
        static readonly ILog log = LogManager.GetLogger(typeof(IdentifyDelta1));

        /// <inheritdoc />
        public string Name { get; } = "p2p/id/delta";

        /// <inheritdoc />
        public SemVersion Version { get; } = new SemVersion(1, 0);

        /// <inheritdoc />
        public override string ToString() => $"/{Name}/{Version}";

        /// <summary>
        ///   The swarm that manages peer connections.
        /// </summary>
        public Swarm Swarm { get; set; }

        /// <inheritdoc />
        public async Task ProcessMessageAsync(PeerConnection connection, Stream stream, CancellationToken cancel = default)
        {
            log.Debug($"Receiving identify delta from {connection.RemoteAddress}");

            var delta = await ProtoBufHelper.ReadMessageAsync<IdentifyDeltaMessage>(stream, cancel).ConfigureAwait(false);

            var remote = connection.RemotePeer;
            if (remote == null)
            {
                log.Warn("Received identify delta but no remote peer on connection");
                return;
            }

            // Apply address additions
            if (delta.AddedAddresses != null)
            {
                var newAddrs = delta.AddedAddresses
                    .Select(b => MultiAddress.TryCreate(b))
                    .Where(a => a != null)
                    .Select(a => a.WithPeerId(remote.Id));

                remote.Addresses = remote.Addresses.Union(newAddrs).ToList();
            }

            // Apply address removals
            if (delta.RemovedAddresses != null)
            {
                var removeSet = new HashSet<string>(
                    delta.RemovedAddresses
                        .Select(b => MultiAddress.TryCreate(b))
                        .Where(a => a != null)
                        .Select(a => a.WithPeerId(remote.Id).ToString()));

                remote.Addresses = remote.Addresses
                    .Where(a => !removeSet.Contains(a.ToString()))
                    .ToList();
            }

            // Update protocols if provided
            if (delta.AddedProtocols != null || delta.RemovedProtocols != null)
            {
                log.Debug($"Protocol delta for {remote}: +{delta.AddedProtocols?.Length ?? 0} -{delta.RemovedProtocols?.Length ?? 0}");
            }

            log.Debug($"Applied identify delta for {remote}");
        }

        /// <summary>
        ///   Send an address delta to a specific peer.
        /// </summary>
        public async Task SendDeltaAsync(
            PeerConnection connection,
            IEnumerable<MultiAddress> addedAddresses,
            IEnumerable<MultiAddress> removedAddresses,
            CancellationToken cancel = default)
        {
            log.Debug($"Sending identify delta to {connection.RemoteAddress}");

            var msg = new IdentifyDeltaMessage
            {
                AddedAddresses = addedAddresses?
                    .Select(a => a.WithoutPeerId().ToArray())
                    .ToArray(),
                RemovedAddresses = removedAddresses?
                    .Select(a => a.WithoutPeerId().ToArray())
                    .ToArray()
            };

            var muxer = await connection.MuxerEstablished.Task.ConfigureAwait(false);
            using var stream = await muxer.CreateStreamAsync("id-delta", cancel).ConfigureAwait(false);
            await connection.EstablishProtocolAsync("/multistream/", stream, cancel).ConfigureAwait(false);
            await connection.EstablishProtocolAsync("/p2p/id/delta/", stream, cancel).ConfigureAwait(false);

            Serializer.SerializeWithLengthPrefix(stream, msg, PrefixStyle.Base128);
            await stream.FlushAsync(cancel).ConfigureAwait(false);
        }

        /// <summary>
        ///   Broadcast address delta to all connected peers.
        /// </summary>
        public async Task BroadcastDeltaAsync(
            IEnumerable<MultiAddress> addedAddresses,
            IEnumerable<MultiAddress> removedAddresses,
            CancellationToken cancel = default)
        {
            if (Swarm == null)
                return;

            var connections = Swarm.Manager.Connections.ToArray();
            foreach (var connection in connections)
            {
                try
                {
                    await SendDeltaAsync(connection, addedAddresses, removedAddresses, cancel).ConfigureAwait(false);
                }
                catch (Exception e)
                {
                    log.Debug($"Failed to send identify delta to {connection.RemoteAddress}: {e.Message}");
                }
            }
        }

        [ProtoContract]
        internal class IdentifyDeltaMessage
        {
            [ProtoMember(1)]
            public byte[][] AddedAddresses;

            [ProtoMember(2)]
            public byte[][] RemovedAddresses;

            [ProtoMember(3)]
            public string[] AddedProtocols;

            [ProtoMember(4)]
            public string[] RemovedProtocols;
        }
    }
}
