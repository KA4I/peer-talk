using Common.Logging;
using Ipfs;
using PeerTalk.Protocols;
using ProtoBuf;
using Semver;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PeerTalk.PubSub
{
    /// <summary>
    ///   GossipSub router implementing the mesh-based pubsub protocol.
    /// </summary>
    /// <remarks>
    ///   See https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/README.md
    ///   Supports GossipSub v1.1 (peer scoring, flood publishing) and
    ///   v1.2 (IDONTWANT) features.
    ///   Uses the same protobuf RPC format as FloodSub.
    /// </remarks>
    public class GossipRouter : IPeerProtocol, IMessageRouter
    {
        static readonly ILog log = LogManager.GetLogger(typeof(GossipRouter));

        readonly MessageTracker tracker = new MessageTracker();
        readonly ConcurrentDictionary<string, string> localTopics = new ConcurrentDictionary<string, string>();

        // Mesh and fanout maps: topic -> set of peer IDs
        readonly ConcurrentDictionary<string, ConcurrentDictionary<string, Peer>> mesh = new();
        readonly ConcurrentDictionary<string, ConcurrentDictionary<string, Peer>> fanout = new();

        // GossipSub parameters (v1.1 defaults)
        const int D = 6;       // desired mesh degree
        const int Dlo = 4;     // low watermark
        const int Dhi = 12;    // high watermark
        const int Dlazy = 6;   // gossip target
        const int HeartbeatIntervalMs = 1000;
        const int FanoutTtlMs = 60000; // fanout TTL

        Timer heartbeatTimer;

        // v1.1: Peer scoring
        readonly ConcurrentDictionary<string, PeerScore> peerScores = new();
        readonly ConcurrentDictionary<string, DateTime> fanoutLastPublish = new();

        // v1.2: IDONTWANT tracking
        readonly ConcurrentDictionary<string, HashSet<string>> iDontWantSets = new();

        // v1.1: Flood publish — always forward own messages to all connected peers
        // regardless of mesh membership (for direct peers / floodsub compat)
        bool floodPublish = true;

        /// <summary>
        ///   Gets or sets whether flood publishing is enabled.
        /// </summary>
        /// <value>
        ///   Defaults to <b>true</b> per GossipSub v1.1.
        /// </value>
        public bool FloodPublish { get => floodPublish; set => floodPublish = value; }

        /// <summary>
        ///   The topics of interest of other peers.
        /// </summary>
        public TopicManager RemoteTopics { get; set; } = new TopicManager();

        /// <inheritdoc />
        public event EventHandler<PublishedMessage> MessageReceived;

        /// <inheritdoc />
        public string Name { get; } = "meshsub";

        /// <inheritdoc />
        public SemVersion Version { get; } = new SemVersion(1, 2, 0);

        /// <inheritdoc />
        public override string ToString() => $"/{Name}/{Version}";

        /// <summary>
        ///   Provides access to other peers.
        /// </summary>
        public Swarm Swarm { get; set; }

        /// <inheritdoc />
        public Task StartAsync()
        {
            log.Debug("Starting GossipSub");
            Swarm.AddProtocol(this);
            Swarm.ConnectionEstablished += Swarm_ConnectionEstablished;
            Swarm.PeerDisconnected += Swarm_PeerDisconnected;

            heartbeatTimer = new Timer(_ => Heartbeat(), null, HeartbeatIntervalMs, HeartbeatIntervalMs);
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public Task StopAsync()
        {
            log.Debug("Stopping GossipSub");
            heartbeatTimer?.Dispose();
            heartbeatTimer = null;

            Swarm.ConnectionEstablished -= Swarm_ConnectionEstablished;
            Swarm.PeerDisconnected -= Swarm_PeerDisconnected;
            Swarm.RemoveProtocol(this);
            RemoteTopics.Clear();
            localTopics.Clear();
            mesh.Clear();
            fanout.Clear();
            peerScores.Clear();
            fanoutLastPublish.Clear();
            iDontWantSets.Clear();

            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public async Task ProcessMessageAsync(PeerConnection connection, Stream stream, CancellationToken cancel = default)
        {
            while (true)
            {
                var request = await ProtoBufHelper.ReadMessageAsync<GossipSubRpc>(stream, cancel).ConfigureAwait(false);

                if (request.Subscriptions != null)
                {
                    foreach (var sub in request.Subscriptions)
                        ProcessSubscription(sub, connection.RemotePeer);
                }

                if (request.PublishedMessages != null)
                {
                    foreach (var msg in request.PublishedMessages)
                    {
                        msg.Forwarder = connection.RemotePeer;
                        MessageReceived?.Invoke(this, msg);
                        await PublishAsync(msg, cancel).ConfigureAwait(false);
                    }
                }

                // Process GossipSub control messages
                if (request.Control != null)
                    ProcessControl(request.Control, connection.RemotePeer);
            }
        }

        public void ProcessSubscription(Subscription sub, Peer remote)
        {
            if (sub.Subscribe)
            {
                RemoteTopics.AddInterest(sub.Topic, remote);
                // If we have a mesh for this topic, consider adding them
                if (mesh.TryGetValue(sub.Topic, out var topicMesh))
                {
                    var peerId = remote.Id.ToString();
                    if (topicMesh.Count < D)
                        topicMesh.TryAdd(peerId, remote);
                }
            }
            else
            {
                RemoteTopics.RemoveInterest(sub.Topic, remote);
                // Remove from mesh
                if (mesh.TryGetValue(sub.Topic, out var topicMesh))
                    topicMesh.TryRemove(remote.Id.ToString(), out _);
            }
        }

        void ProcessControl(ControlMessage control, Peer remote)
        {
            // GRAFT: peer wants to join our mesh for a topic
            if (control.Graft != null)
            {
                foreach (var graft in control.Graft)
                {
                    if (!string.IsNullOrEmpty(graft.TopicId) && mesh.TryGetValue(graft.TopicId, out var topicMesh))
                    {
                        topicMesh.TryAdd(remote.Id.ToString(), remote);
                    }
                }
            }

            // PRUNE: peer is leaving our mesh for a topic
            if (control.Prune != null)
            {
                foreach (var prune in control.Prune)
                {
                    if (!string.IsNullOrEmpty(prune.TopicId) && mesh.TryGetValue(prune.TopicId, out var topicMesh))
                    {
                        topicMesh.TryRemove(remote.Id.ToString(), out _);
                    }
                }
            }

            // IHAVE: peer tells us about messages they have (gossip)
            if (control.Ihave != null)
            {
                var iwants = new List<string>();
                foreach (var ihave in control.Ihave)
                {
                    if (ihave.MessageIds != null)
                    {
                        foreach (var msgId in ihave.MessageIds)
                        {
                            if (!tracker.RecentlySeen(msgId))
                                iwants.Add(msgId);
                        }
                    }
                }
                if (iwants.Count > 0)
                    _ = SendIWantAsync(remote, iwants);
            }

            // IWANT: peer wants specific messages from us
            // We don't cache messages in this implementation

            // v1.2: IDONTWANT: peer tells us not to send certain messages
            if (control.Idontwant != null)
            {
                foreach (var idontwant in control.Idontwant)
                {
                    if (idontwant.MessageIds != null)
                    {
                        var peerId = remote.Id.ToString();
                        var dontWant = iDontWantSets.GetOrAdd(peerId, _ => new HashSet<string>());
                        lock (dontWant)
                        {
                            foreach (var msgId in idontwant.MessageIds)
                                dontWant.Add(msgId);
                        }
                    }
                }
            }
        }

        /// <inheritdoc />
        public IEnumerable<Peer> InterestedPeers(string topic) => RemoteTopics.GetPeers(topic);

        /// <inheritdoc />
        public async Task JoinTopicAsync(string topic, CancellationToken cancel)
        {
            localTopics.TryAdd(topic, topic);

            // Create mesh for this topic
            var topicMesh = mesh.GetOrAdd(topic, _ => new ConcurrentDictionary<string, Peer>());

            // Add interested peers to mesh up to D
            var peers = RemoteTopics.GetPeers(topic).Take(D);
            foreach (var p in peers)
                topicMesh.TryAdd(p.Id.ToString(), p);

            // Send GRAFT to mesh peers 
            foreach (var peer in topicMesh.Values)
                _ = SendGraftAsync(peer, topic);

            // Also send subscription to all connected peers
            var msg = new GossipSubRpc
            {
                Subscriptions = new[] { new Subscription { Topic = topic, Subscribe = true } }
            };
            try
            {
                var connectedPeers = Swarm.KnownPeers.Where(p => p.ConnectedAddress != null);
                await SendAsync(msg, connectedPeers, cancel).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                log.Warn("Join topic failed.", e);
            }
        }

        /// <inheritdoc />
        public async Task LeaveTopicAsync(string topic, CancellationToken cancel)
        {
            localTopics.TryRemove(topic, out _);

            // Send PRUNE to mesh peers and remove mesh
            if (mesh.TryRemove(topic, out var topicMesh))
            {
                foreach (var peer in topicMesh.Values)
                    _ = SendPruneAsync(peer, topic);
            }

            var msg = new GossipSubRpc
            {
                Subscriptions = new[] { new Subscription { Topic = topic, Subscribe = false } }
            };
            try
            {
                var connectedPeers = Swarm.KnownPeers.Where(p => p.ConnectedAddress != null);
                await SendAsync(msg, connectedPeers, cancel).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                log.Warn("Leave topic failed.", e);
            }
        }

        /// <inheritdoc />
        public Task PublishAsync(PublishedMessage message, CancellationToken cancel)
        {
            if (tracker.RecentlySeen(message.MessageId))
                return Task.CompletedTask;

            // v1.1: Flood publish — if this is OUR message, send to all connected peers
            bool isOwnMessage = message.Sender == Swarm?.LocalPeer;

            // Send to mesh peers for each topic
            var meshPeers = new HashSet<string>();
            foreach (var topic in message.Topics)
            {
                if (mesh.TryGetValue(topic, out var topicMesh))
                {
                    foreach (var kvp in topicMesh)
                    {
                        if (kvp.Value != message.Sender && kvp.Value != message.Forwarder)
                            meshPeers.Add(kvp.Key);
                    }
                }
                else if (fanout.TryGetValue(topic, out var fanoutPeers))
                {
                    // We're not subscribed but we published — use fanout
                    fanoutLastPublish[topic] = DateTime.UtcNow;
                    foreach (var kvp in fanoutPeers)
                    {
                        if (kvp.Value != message.Sender && kvp.Value != message.Forwarder)
                            meshPeers.Add(kvp.Key);
                    }
                }
                else
                {
                    // No mesh or fanout — create fanout from interested peers
                    var interested = RemoteTopics.GetPeers(topic)
                        .Where(p => p != message.Sender && p != message.Forwarder)
                        .Take(D);
                    var fanoutMap = new ConcurrentDictionary<string, Peer>();
                    foreach (var p in interested)
                    {
                        fanoutMap.TryAdd(p.Id.ToString(), p);
                        meshPeers.Add(p.Id.ToString());
                    }
                    fanout.TryAdd(topic, fanoutMap);
                    fanoutLastPublish[topic] = DateTime.UtcNow;
                }
            }

            // v1.1: Flood publish — send to ALL connected peers for own messages
            if (isOwnMessage && floodPublish)
            {
                var connectedPeers = Swarm?.KnownPeers
                    .Where(p => p.ConnectedAddress != null && p != message.Sender);
                if (connectedPeers != null)
                {
                    foreach (var p in connectedPeers)
                        meshPeers.Add(p.Id.ToString());
                }
            }

            // v1.2: Filter out peers that sent IDONTWANT for this message
            var msgId = message.MessageId;
            var filteredPeerIds = meshPeers.Where(pid =>
            {
                if (iDontWantSets.TryGetValue(pid, out var dontWant))
                {
                    lock (dontWant)
                    {
                        return !dontWant.Contains(msgId);
                    }
                }
                return true;
            });

            // Collect actual peer objects
            var peersToSend = filteredPeerIds
                .Select(id =>
                {
                    foreach (var topicMeshKvp in mesh.Values.Concat(fanout.Values))
                    {
                        if (topicMeshKvp.TryGetValue(id, out var p))
                            return p;
                    }
                    // For flood-published messages, find from known peers
                    return Swarm?.KnownPeers.FirstOrDefault(p => p.Id.ToString() == id);
                })
                .Where(p => p != null);

            // v1.2: Send IDONTWANT to mesh peers to reduce redundant sends
            if (message.DataBytes?.Length > 1024)
            {
                _ = SendIDontWantAsync(meshPeers, message.MessageId);
            }

            var forward = new GossipSubRpc
            {
                PublishedMessages = new[] { message }
            };

            return SendAsync(forward, peersToSend, cancel);
        }

        /// <summary>
        ///   Periodic heartbeat: maintain mesh, emit gossip, manage fanout TTL, decay scores.
        /// </summary>
        void Heartbeat()
        {
            foreach (var topicKvp in mesh)
            {
                var topic = topicKvp.Key;
                var topicMesh = topicKvp.Value;

                // Prune excess peers (prefer lower-scored peers for pruning)
                while (topicMesh.Count > Dhi)
                {
                    // v1.1: prune lowest scoring peer
                    var toRemove = topicMesh.Keys
                        .OrderBy(pid => GetPeerScore(pid))
                        .FirstOrDefault();
                    if (toRemove != null && topicMesh.TryRemove(toRemove, out var peer))
                        _ = SendPruneAsync(peer, topic);
                }

                // Graft more peers if below Dlo (prefer higher-scored peers)
                if (topicMesh.Count < Dlo)
                {
                    var candidates = RemoteTopics.GetPeers(topic)
                        .Where(p => !topicMesh.ContainsKey(p.Id.ToString()))
                        .Where(p => GetPeerScore(p.Id.ToString()) >= 0)
                        .Take(D - topicMesh.Count);
                    foreach (var p in candidates)
                    {
                        topicMesh.TryAdd(p.Id.ToString(), p);
                        _ = SendGraftAsync(p, topic);
                    }
                }

                // v1.1: Emit IHAVE gossip about recently seen messages
                EmitGossip(topic, topicMesh);
            }

            // v1.1: Expire fanout entries past TTL
            foreach (var kvp in fanoutLastPublish)
            {
                if ((DateTime.UtcNow - kvp.Value).TotalMilliseconds > FanoutTtlMs)
                {
                    fanout.TryRemove(kvp.Key, out _);
                    fanoutLastPublish.TryRemove(kvp.Key, out _);
                }
            }

            // v1.1: Decay peer scores
            foreach (var kvp in peerScores)
            {
                kvp.Value.Decay();
            }

            // v1.2: Clear IDONTWANT sets periodically
            iDontWantSets.Clear();
        }

        void EmitGossip(string topic, ConcurrentDictionary<string, Peer> topicMesh)
        {
            var recentMsgIds = tracker.GetRecentMessageIds(Dlazy);
            if (recentMsgIds == null || recentMsgIds.Length == 0) return;

            // Send IHAVE to random non-mesh peers interested in this topic
            var nonMeshPeers = RemoteTopics.GetPeers(topic)
                .Where(p => !topicMesh.ContainsKey(p.Id.ToString()))
                .Take(Dlazy);

            foreach (var peer in nonMeshPeers)
            {
                var rpc = new GossipSubRpc
                {
                    Control = new ControlMessage
                    {
                        Ihave = new[] { new ControlIHave { TopicId = topic, MessageIds = recentMsgIds } }
                    }
                };
                _ = SendAsync(rpc, new[] { peer }, CancellationToken.None);
            }
        }

        Task SendIDontWantAsync(IEnumerable<string> peerIds, string messageId)
        {
            var tasks = new List<Task>();
            foreach (var pid in peerIds)
            {
                Peer peer = null;
                foreach (var topicMeshKvp in mesh.Values)
                {
                    if (topicMeshKvp.TryGetValue(pid, out peer))
                        break;
                }
                if (peer == null) continue;

                var rpc = new GossipSubRpc
                {
                    Control = new ControlMessage
                    {
                        Idontwant = new[] { new ControlIDontWant { MessageIds = new[] { messageId } } }
                    }
                };
                tasks.Add(SendAsync(rpc, new[] { peer }, CancellationToken.None));
            }
            return Task.WhenAll(tasks);
        }

        double GetPeerScore(string peerId)
        {
            return peerScores.TryGetValue(peerId, out var score) ? score.Value : 0;
        }

        /// <summary>
        ///   Record a positive behavior for a peer (e.g., delivered a useful message).
        /// </summary>
        public void AddPeerScore(Peer peer, double delta)
        {
            var score = peerScores.GetOrAdd(peer.Id.ToString(), _ => new PeerScore());
            score.Value += delta;
        }

        Task SendGraftAsync(Peer peer, string topic)
        {
            var rpc = new GossipSubRpc
            {
                Control = new ControlMessage
                {
                    Graft = new[] { new ControlGraft { TopicId = topic } }
                }
            };
            return SendAsync(rpc, new[] { peer }, CancellationToken.None);
        }

        Task SendPruneAsync(Peer peer, string topic)
        {
            var rpc = new GossipSubRpc
            {
                Control = new ControlMessage
                {
                    Prune = new[] { new ControlPrune { TopicId = topic } }
                }
            };
            return SendAsync(rpc, new[] { peer }, CancellationToken.None);
        }

        Task SendIWantAsync(Peer peer, List<string> messageIds)
        {
            var rpc = new GossipSubRpc
            {
                Control = new ControlMessage
                {
                    Iwant = new[] { new ControlIWant { MessageIds = messageIds.ToArray() } }
                }
            };
            return SendAsync(rpc, new[] { peer }, CancellationToken.None);
        }

        Task SendAsync(GossipSubRpc msg, IEnumerable<Peer> peers, CancellationToken cancel)
        {
            byte[] bin;
            using (var ms = new MemoryStream())
            {
                Serializer.SerializeWithLengthPrefix(ms, msg, PrefixStyle.Base128);
                bin = ms.ToArray();
            }
            return Task.WhenAll(peers.Select(p => SendAsync(bin, p, cancel)));
        }

        async Task SendAsync(byte[] message, Peer peer, CancellationToken cancel)
        {
            try
            {
                using var stream = await Swarm.DialAsync(peer, this.ToString(), cancel).ConfigureAwait(false);
                await stream.WriteAsync(message, 0, message.Length, cancel).ConfigureAwait(false);
                await stream.FlushAsync(cancel).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                log.Debug($"{peer} refused gossipsub message.", e);
            }
        }

#pragma warning disable VSTHRD100
        async void Swarm_ConnectionEstablished(object sender, PeerConnection connection)
#pragma warning restore VSTHRD100
        {
            if (localTopics.Count == 0) return;
            try
            {
                var hello = new GossipSubRpc
                {
                    Subscriptions = localTopics.Values
                        .Select(t => new Subscription { Subscribe = true, Topic = t })
                        .ToArray()
                };
                await SendAsync(hello, new[] { connection.RemotePeer }, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                log.Warn("Sending hello message failed", e);
            }
        }

        void Swarm_PeerDisconnected(object sender, Peer peer)
        {
            RemoteTopics.Clear(peer);
            var peerId = peer.Id.ToString();
            foreach (var topicMesh in mesh.Values)
                topicMesh.TryRemove(peerId, out _);
            foreach (var fanoutPeers in fanout.Values)
                fanoutPeers.TryRemove(peerId, out _);
            peerScores.TryRemove(peerId, out _);
            iDontWantSets.TryRemove(peerId, out _);
        }

        // --- Protobuf messages for GossipSub RPC ---

        [ProtoContract]
        internal class GossipSubRpc
        {
            [ProtoMember(1)]
            public Subscription[] Subscriptions;

            [ProtoMember(2)]
            public PublishedMessage[] PublishedMessages;

            [ProtoMember(3)]
            public ControlMessage Control;
        }

        [ProtoContract]
        internal class ControlMessage
        {
            [ProtoMember(1)]
            public ControlIHave[] Ihave;

            [ProtoMember(2)]
            public ControlIWant[] Iwant;

            [ProtoMember(3)]
            public ControlGraft[] Graft;

            [ProtoMember(4)]
            public ControlPrune[] Prune;

            [ProtoMember(5)]
            public ControlIDontWant[] Idontwant;
        }

        [ProtoContract]
        internal class ControlIHave
        {
            [ProtoMember(1)]
            public string TopicId;

            [ProtoMember(2)]
            public string[] MessageIds;
        }

        [ProtoContract]
        internal class ControlIWant
        {
            [ProtoMember(1)]
            public string[] MessageIds;
        }

        [ProtoContract]
        internal class ControlGraft
        {
            [ProtoMember(1)]
            public string TopicId;
        }

        [ProtoContract]
        internal class ControlPrune
        {
            [ProtoMember(1)]
            public string TopicId;

            [ProtoMember(2)]
            public PeerInfo[] Peers;

            [ProtoMember(3)]
            public ulong Backoff;
        }

        [ProtoContract]
        internal class PeerInfo
        {
            [ProtoMember(1)]
            public byte[] PeerId;

            [ProtoMember(2)]
            public SignedPeerRecord SignedPeerRecord;
        }

        [ProtoContract]
        internal class SignedPeerRecord
        {
            [ProtoMember(1)]
            public byte[] Envelope;
        }

        [ProtoContract]
        internal class ControlIDontWant
        {
            [ProtoMember(1)]
            public string[] MessageIds;
        }

        /// <summary>
        ///   Tracks a peer's score for mesh prioritization (v1.1).
        /// </summary>
        internal class PeerScore
        {
            public double Value { get; set; }
            const double DecayFactor = 0.99;
            public void Decay() => Value *= DecayFactor;
        }
    }
}
