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
    ///   Identify Push protocol — allows a peer to proactively push
    ///   updated identity information to connected peers.
    /// </summary>
    /// <remarks>
    ///   Protocol ID: /ipfs/id/push/1.0.0
    ///   <para>
    ///   See https://github.com/libp2p/specs/blob/master/identify/README.md
    ///   </para>
    /// </remarks>
    public class IdentifyPush1 : IPeerProtocol
    {
        static readonly ILog log = LogManager.GetLogger(typeof(IdentifyPush1));

        /// <inheritdoc />
        public string Name { get; } = "ipfs/id/push";

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
            // A remote peer is pushing its updated identity to us.
            log.Debug($"Receiving identify push from {connection.RemoteAddress}");

            var info = await ProtoBufHelper.ReadMessageAsync<IdentifyMessage>(stream, cancel).ConfigureAwait(false);

            var remote = connection.RemotePeer;
            if (remote == null)
            {
                log.Warn("Received identify push but no remote peer on connection");
                return;
            }

            // Update peer information
            if (!string.IsNullOrEmpty(info.AgentVersion))
                remote.AgentVersion = info.AgentVersion;
            if (!string.IsNullOrEmpty(info.ProtocolVersion))
                remote.ProtocolVersion = info.ProtocolVersion;

            if (info.ListenAddresses != null)
            {
                remote.Addresses = info.ListenAddresses
                    .Select(b => MultiAddress.TryCreate(b))
                    .Where(a => a != null)
                    .Select(a => a.WithPeerId(remote.Id))
                    .ToList();
            }

            log.Debug($"Updated identity for {remote} via push");
        }

        /// <summary>
        ///   Push our identity to a specific peer.
        /// </summary>
        /// <param name="connection">The connection to the remote peer.</param>
        /// <param name="cancel">Cancellation token.</param>
        public async Task PushAsync(PeerConnection connection, CancellationToken cancel = default)
        {
            var peer = connection.LocalPeer;
            log.Debug($"Pushing identity to {connection.RemoteAddress}");

            var msg = new IdentifyMessage
            {
                ProtocolVersion = peer.ProtocolVersion,
                AgentVersion = peer.AgentVersion,
                ListenAddresses = peer.Addresses
                    .Select(a => a.WithoutPeerId().ToArray())
                    .ToArray(),
                ObservedAddress = connection.RemoteAddress?.ToArray(),
            };
            if (peer.PublicKey != null)
            {
                msg.PublicKey = Convert.FromBase64String(peer.PublicKey);
            }

            var muxer = await connection.MuxerEstablished.Task.ConfigureAwait(false);
            using var stream = await muxer.CreateStreamAsync("id-push", cancel).ConfigureAwait(false);
            await connection.EstablishProtocolAsync("/multistream/", stream, cancel).ConfigureAwait(false);
            await connection.EstablishProtocolAsync("/ipfs/id/push/", stream, cancel).ConfigureAwait(false);

            Serializer.SerializeWithLengthPrefix(stream, msg, PrefixStyle.Base128);
            await stream.FlushAsync(cancel).ConfigureAwait(false);
        }

        /// <summary>
        ///   Push our identity to all connected peers.
        /// </summary>
        /// <param name="cancel">Cancellation token.</param>
        public async Task PushToAllAsync(CancellationToken cancel = default)
        {
            if (Swarm == null)
                return;

            var connections = Swarm.Manager.Connections.ToArray();
            foreach (var connection in connections)
            {
                try
                {
                    await PushAsync(connection, cancel).ConfigureAwait(false);
                }
                catch (Exception e)
                {
                    log.Debug($"Failed to push identity to {connection.RemoteAddress}: {e.Message}");
                }
            }
        }

        [ProtoContract]
        internal class IdentifyMessage
        {
            [ProtoMember(5)]
            public string ProtocolVersion;
            [ProtoMember(6)]
            public string AgentVersion;
            [ProtoMember(1)]
            public byte[] PublicKey;
            [ProtoMember(2, IsRequired = true)]
            public byte[][] ListenAddresses;
            [ProtoMember(4)]
            public byte[] ObservedAddress;
            [ProtoMember(3)]
            public string[] Protocols;
        }
    }
}
