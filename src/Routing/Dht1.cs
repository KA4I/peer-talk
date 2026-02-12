using Common.Logging;
using Ipfs;
using Ipfs.CoreApi;
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


namespace PeerTalk.Routing
{
    /// <summary>
    ///   DHT Protocol version 1.0
    /// </summary>
    public class Dht1 : IPeerProtocol, IService, IPeerRouting, IContentRouting, IValueStore
    {
        static ILog log = LogManager.GetLogger(typeof(Dht1));

        /// <inheritdoc />
        public string Name { get; } = "ipfs/kad";

        /// <inheritdoc />
        public SemVersion Version { get; } = new SemVersion(1, 0);

        /// <summary>
        ///   Provides access to other peers.
        /// </summary>
        public Swarm Swarm { get; set; }

        /// <summary>
        /// Provides storage for DHT key value pairs
        /// </summary>
        public IDataStore<byte[], DhtRecord> DataStore { get; set; }

        /// <summary>
        ///  Routing information on peers.
        /// </summary>
        public RoutingTable RoutingTable;

        /// <summary>
        ///   Peers that can provide some content.
        /// </summary>
        public ContentRouter ContentRouter;

        /// <summary>
        ///   The number of closer peers to return.
        /// </summary>
        /// <value>
        ///   Defaults to 20.
        /// </value>
        public int CloserPeerCount { get; set; } = 20;

        /// <summary>
        ///   Raised when the DHT is stopped.
        /// </summary>
        /// <seealso cref="StopAsync"/>
        public event EventHandler Stopped;

        /// <summary>
        /// The Selector to use to determine the best record when getting records from the DHT
        /// </summary>
        public Selector Selector { get; set; }

        /// <inheritdoc />
        public override string ToString()
        {
            return $"/{Name}/{Version}";
        }

        /// <inheritdoc />
        public async Task ProcessMessageAsync(PeerConnection connection, Stream stream, CancellationToken cancel = default(CancellationToken))
        {
            while (true)
            {
                var request = await ProtoBufHelper.ReadMessageAsync<DhtMessage>(stream, cancel).ConfigureAwait(false);

                log.Debug($"got {request.Type} from {connection.RemotePeer}");
                var response = new DhtMessage
                {
                    Type = request.Type,
                    ClusterLevelRaw = request.ClusterLevelRaw
                };
                switch (request.Type)
                {
                    case MessageType.Ping:
                        response = ProcessPing(request, response);
                        break;
                    case MessageType.FindNode:
                        response = ProcessFindNode(request, response);
                        break;
                    case MessageType.GetProviders:
                        response = ProcessGetProviders(request, response);
                        break;
                    case MessageType.AddProvider:
                        response = ProcessAddProvider(connection.RemotePeer, request, response);
                        break;
                    case MessageType.GetValue:
                        response = await ProcessGetValueAsync(connection.RemotePeer, request, response, cancel);
                        break;
                    case MessageType.PutValue:
                        response = await ProcessPutValueAsync(connection.RemotePeer, request, response, cancel);
                        break;
                    default:
                        log.Debug($"unknown {request.Type} from {connection.RemotePeer}");
                        // TODO: Should we close the stream?
                        continue;
                }
                if (response != null)
                {
                    ProtoBuf.Serializer.SerializeWithLengthPrefix(stream, response, PrefixStyle.Base128);
                    await stream.FlushAsync(cancel).ConfigureAwait(false);
                }
            }
        }

        /// <inheritdoc />
        public Task StartAsync()
        {
            log.Debug("Starting");

            RoutingTable = new RoutingTable(Swarm.LocalPeer);
            ContentRouter = new ContentRouter();
            Swarm.AddProtocol(this);
            Swarm.PeerDiscovered += Swarm_PeerDiscovered;
            Swarm.PeerRemoved += Swarm_PeerRemoved;
            foreach (var peer in Swarm.KnownPeers)
            {
                RoutingTable.Add(peer);
            }

            if (this.Selector == null)
            {
                this.Selector = new Selector();
            }

            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public Task StopAsync()
        {
            log.Debug("Stopping");

            Swarm.RemoveProtocol(this);
            Swarm.PeerDiscovered -= Swarm_PeerDiscovered;
            Swarm.PeerRemoved -= Swarm_PeerRemoved;

            Stopped?.Invoke(this, EventArgs.Empty);
            ContentRouter?.Dispose();
            return Task.CompletedTask;
        }

        /// <summary>
        ///   The swarm has discovered a new peer, update the routing table.
        /// </summary>
        void Swarm_PeerDiscovered(object sender, Peer e)
        {
            RoutingTable.Add(e);
        }

        /// <summary>
        ///   The swarm has removed a peer, update the routing table.
        /// </summary>
        private void Swarm_PeerRemoved(object sender, Peer e)
        {
            RoutingTable.Remove(e);
        }

        /// <inheritdoc />
        public async Task<Peer> FindPeerAsync(MultiHash id, CancellationToken cancel = default(CancellationToken))
        {
            // Can always find self.
            if (Swarm.LocalPeer.Id == id)
                return Swarm.LocalPeer;

            // Maybe the swarm knows about it.
            var found = Swarm.KnownPeers.FirstOrDefault(p => p.Id == id);
            if (found != null && found.Addresses.Count() > 0)
                return found;

            // Ask our peers for information on the requested peer.
            var dquery = new DistributedQuery<Peer>
            {
                QueryType = MessageType.FindNode,
                QueryKey = id,
                Dht = this,
                AnswersNeeded = 1
            };
            await dquery.RunAsync(cancel).ConfigureAwait(false);

            // If not found, return the closest peer.
            if (dquery.Answers.Count() == 0)
            {
                return RoutingTable.NearestPeers(id).FirstOrDefault();
            }

            return dquery.Answers.First();
        }

        private async Task<IEnumerable<Peer>> GetClosestPeersAsync(byte[] key, CancellationToken cancel = default(CancellationToken))
        {
            var id = new MultiHash(key);

            // js-libp2p uses 20 as number to query https://github.com/libp2p/js-libp2p-kad-dht/blob/1f02658d82bfbcbde7ead97149fdd0b70d711d4a/src/index.js#L48
            const int closestPeersToReturn = 20; 

            // we ask our local peers to all go find the closest peers
            var dQuery = new DistributedQuery<Peer>()
            {
                AnswersNeeded = closestPeersToReturn,
                Dht = this,
                QueryKey = id,
                QueryType = MessageType.FindNode,
                Shallow = true
            };
            await dQuery.RunAsync(cancel).ConfigureAwait(false);

            // the closest peers will have been added to the routingtable so we can now return those
            return this.RoutingTable.NearestPeers(id).Take(closestPeersToReturn).ToArray();
        }

        /// <inheritdoc />
        public Task ProvideAsync(Cid cid, bool advertise = true, CancellationToken cancel = default(CancellationToken))
        {
            ContentRouter.Add(cid, this.Swarm.LocalPeer.Id);
            if (advertise)
            {
                Advertise(cid);
            }

            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public async Task<IEnumerable<Peer>> FindProvidersAsync(
            Cid id,
            int limit = 20,
            Action<Peer> action = null,
            CancellationToken cancel = default(CancellationToken))
        {
            var dquery = new DistributedQuery<Peer>
            {
                QueryType = MessageType.GetProviders,
                QueryKey = id.Hash,
                Dht = this,
                AnswersNeeded = limit,
            };
            if (action != null)
            {
                dquery.AnswerObtained += (s, e) => action.Invoke(e);
            }

            // Add any providers that we already know about.
            var providers = ContentRouter
                .Get(id)
                .Select(pid =>
                {
                    return (pid == Swarm.LocalPeer.Id)
                        ? Swarm.LocalPeer
                        : Swarm.RegisterPeer(new Peer { Id = pid });
                });
            foreach (var provider in providers)
            {
                dquery.AddAnswer(provider);
            }

            // Ask our peers for more providers.
            if (limit > dquery.Answers.Count())
            {
                await dquery.RunAsync(cancel).ConfigureAwait(false);
            }

            return dquery.Answers.Take(limit);
        }

        /// <summary>
        ///   Advertise that we can provide the CID to the X closest peers
        ///   of the CID.
        /// </summary>
        /// <param name="cid">
        ///   The CID to advertise.
        /// </param>
        /// <remarks>
        ///   This starts a background process to send the AddProvider message
        ///   to the 4 closest peers to the <paramref name="cid"/>.
        /// </remarks>
        public void Advertise(Cid cid)
        {
            _ = Task.Run(async () =>
            {
                int advertsNeeded = 4;
                var message = new DhtMessage
                {
                    Type = MessageType.AddProvider,
                    Key = cid.Hash.ToArray(),
                    ProviderPeers = new DhtPeerMessage[]
                    {
                        new DhtPeerMessage
                        {
                            Id = Swarm.LocalPeer.Id.ToArray(),
                            Addresses = Swarm.LocalPeer.Addresses
                                .Select(a => a.WithoutPeerId().ToArray())
                                .ToArray()
                        }
                    }
                };
                var peers = RoutingTable
                    .NearestPeers(cid.Hash)
                    .Where(p => p != Swarm.LocalPeer);   
                foreach (var peer in peers)
                {
                    try
                    {
                        using (var stream = await Swarm.DialAsync(peer, this.ToString()))
                        {
                            ProtoBuf.Serializer.SerializeWithLengthPrefix(stream, message, PrefixStyle.Base128);
                            await stream.FlushAsync();
                        }
                        if (--advertsNeeded == 0)
                            break;
                    }
                    catch (Exception)
                    {
                        // eat it.  This is fire and forget.
                    }
                }
            });
        }

        /// <summary>
        ///   Process a ping request.
        /// </summary>
        /// <remarks>
        ///   Simply return the <paramref name="request"/>.
        /// </remarks>
        DhtMessage ProcessPing(DhtMessage request, DhtMessage response)
        {
            return request;
        }

        private async Task<DhtMessage> ProcessPutValueAsync(Peer remotePeer, DhtMessage request, DhtMessage response,
            CancellationToken cancel)
        {
            if (request.Record?.Value != null)
            {
                await this.PutLocalAsync(request.Key, request.Record.Value, cancel);
            }

            response.Record = request.Record;
            return response;
        }

        private async Task<DhtMessage> ProcessGetValueAsync(Peer remotePeer, DhtMessage request, DhtMessage response,
            CancellationToken cancel)
        {
            if (IsPublicKeyKey(request.Key))
            {
                var peerId = new MultiHash(request.Key.Skip(4).ToArray());
                var peer = TryFindPeer(peerId);
                AddCloserPeers(response, peerId, peer);
                response.Record = new DhtRecordMessage(request.Key, peerId.ToArray());
                return response;
            }

            DhtRecord localValue = null;
            if (this.DataStore != null)
            {
                localValue = await this.DataStore.GetAsync(request.Key, cancel);
            }

            if (localValue != null)
            {
                response.Record = new DhtRecordMessage(request.Key, localValue.Value)
                {
                    TimeReceived = DhtRecordMessage.FormatDateTime(localValue.TimeReceived)
                };
            }

            AddCloserPeers(response, new MultiHash(request.Key));
            return response;
        }

        static readonly byte[] publicKeyPrefix = Encoding.UTF8.GetBytes("/pk/");

        private bool IsPublicKeyKey(byte[] key)
        {
            return publicKeyPrefix.SequenceEqual(key);
        }

        /// <summary>
        ///   Process a find node request.
        /// </summary>
        public DhtMessage ProcessFindNode(DhtMessage request, DhtMessage response)
        {
            // Some random walkers generate a random Key that is not hashed.
            MultiHash peerId;
            try
            {
                peerId = new MultiHash(request.Key);
            }
            catch (Exception)
            {
                log.Error($"Bad FindNode request key {request.Key.ToHexString()}");
                peerId = MultiHash.ComputeHash(request.Key);
            }

            // Do we know the peer?.
            var peer = TryFindPeer(peerId);
            AddCloserPeers(response, peerId, peer);

            if (log.IsDebugEnabled)
                log.Debug($"returning {response.CloserPeers.Length} closer peers");
            return response;
        }

        private Peer TryFindPeer(MultiHash peerId)
        {
            Peer found = null;
            if (Swarm.LocalPeer.Id == peerId)
            {
                found = Swarm.LocalPeer;
            }
            else
            {
                found = Swarm.KnownPeers.FirstOrDefault(p => p.Id == peerId);
            }

            return found;
        }

        private void AddCloserPeers(DhtMessage response, MultiHash id, Peer found = null)
        {
            // Find the closer peers.
            var closerPeers = new List<Peer>();
            if (found != null)
            {
                closerPeers.Add(found);
            }
            else
            {
                closerPeers.AddRange(RoutingTable.NearestPeers(id).Take(CloserPeerCount));
            }

            // Build the response.
            response.CloserPeers = closerPeers
                .Select(peer => new DhtPeerMessage
                {
                    Id = peer.Id.ToArray(),
                    Addresses = peer.Addresses.Select(a => a.WithoutPeerId().ToArray()).ToArray()
                })
                .ToArray();
        }

        /// <summary>
        ///   Process a get provider request.
        /// </summary>
        public DhtMessage ProcessGetProviders(DhtMessage request, DhtMessage response)
        {
            // Find providers for the content.
            var cid = new Cid { Hash = new MultiHash(request.Key) };
            response.ProviderPeers = ContentRouter
                .Get(cid)
                .Select(pid =>
                {
                    var peer = (pid == Swarm.LocalPeer.Id)
                         ? Swarm.LocalPeer
                         : Swarm.RegisterPeer(new Peer { Id = pid });
                    return new DhtPeerMessage
                    {
                        Id = peer.Id.ToArray(),
                        Addresses = peer.Addresses.Select(a => a.WithoutPeerId().ToArray()).ToArray()
                    };
                })
                .Take(20)
                .ToArray();

            // Also return the closest peers
            return ProcessFindNode(request, response);
        }

        /// <summary>
        ///   Process an add provider request.
        /// </summary>
        public DhtMessage ProcessAddProvider(Peer remotePeer, DhtMessage request, DhtMessage response)
        {
            if (request.ProviderPeers == null)
            {
                return null;
            }
            Cid cid;
            try
            {
                cid = new Cid { Hash = new MultiHash(request.Key) };
            }
            catch (Exception)
            {
                log.Error($"Bad AddProvider request key {request.Key.ToHexString()}");
                return null;
            }
            var providers = request.ProviderPeers
                .Select(p => p.TryToPeer(out Peer peer) ? peer : (Peer)null)
                .Where(p => p != null)
                .Where(p => p == remotePeer)
                .Where(p => p.Addresses.Count() > 0)
                .Where(p => Swarm.IsAllowed(p));
            foreach (var provider in providers)
            {
                Swarm.RegisterPeer(provider);
                ContentRouter.Add(cid, provider.Id);
            };

            // There is no response for this request.
            return null;
        }

        /// <inheritdoc />
        public async Task<byte[]> GetAsync(byte[] key, CancellationToken cancel = new CancellationToken())
        {
            var value = await GetBestValueAsync(key, cancel);
            if (value == null)
            {
                throw new Exception("Unable to get value for key");
            }

            return value;
        }

        private async Task<byte[]> GetBestValueAsync(byte[] key, CancellationToken cancel)
        {
            log.Debug("Get value");

            // as per https://github.com/libp2p/js-libp2p-kad-dht/blob/master/src/constants.js (seems a bit high though?)
            const int valuesRequired = 16; 

            var id = new MultiHash(key);
            var dQuery = new DistributedQuery<GetValueAnswer>()
            {
                AnswersNeeded = valuesRequired,
                QueryType = MessageType.GetValue,
                QueryKey = id,
                Dht = this
            };

            if (this.DataStore != null)
            {
                var localValue = await this.DataStore.GetAsync(key, cancel);
                if (localValue != null)
                {
                    dQuery.AddAnswer(
                        new GetValueAnswer(
                            new DhtMessage
                            {
                                Key = key, 
                                Type = MessageType.GetValue, 
                                Record = new DhtRecordMessage(key, localValue.Value)
                                {
                                    TimeReceived = DhtRecordMessage.FormatDateTime(localValue.TimeReceived)
                                }
                            }, 
                            this.Swarm.LocalPeer));
                }
            }

            dQuery.OnResponseReceived = (message, peer) =>
            {
                if (message.Record?.Value != null)
                {
                    dQuery.AddAnswer(new GetValueAnswer(message, peer));
                }
            };
            await dQuery.RunAsync(cancel).ConfigureAwait(false);
            if (!dQuery.Answers.Any())
            {
                return null;
            }

            var values = dQuery.Answers.Select(d => d.Message.Record.Value).ToArray();
            var bestRecordIndex = this.Selector.BestRecord(id.ToBase58(), values);
            var best = values[bestRecordIndex];

            await this.SendCorrectionRecordAsync(key, dQuery.Answers, best, cancel);
            return best;
        }

        private async Task SendCorrectionRecordAsync(byte[] key, IEnumerable<GetValueAnswer> answers, byte[] bestValue,
            CancellationToken cancel)
        {
            // update locally
            await this.PutLocalAsync(key, bestValue, cancel);

            // update out of date peers
            var record = new DhtRecordMessage(key, bestValue);
            var incorrectPeers = answers.Where(d => d.Peer != this.Swarm.LocalPeer
                                                    && !d.Message.Record.Value.SequenceEqual(bestValue));
            foreach (var getValueAnswer in incorrectPeers)
            {
                await this.PutValueToPeerAsync(key, record, getValueAnswer.Peer, cancel);
            }
        }

        private async Task PutLocalAsync(byte[] key, byte[] value, CancellationToken cancel)
        {
            if (this.DataStore != null)
            {
                await this.DataStore.PutAsync(key, new DhtRecord(value), cancel);
            }
        }

        /// <inheritdoc />
        public async Task PutAsync(byte[] key, byte[] value, CancellationToken cancel = new CancellationToken())
        {
            log.Debug($"Put value");
            var record = new DhtRecordMessage(key, value);

            // store locally
            await this.PutLocalAsync(key, value, cancel);
            
            // put record to the closest peers
            var counterAll = 0;
            var counterSuccess = 0;
            foreach (var peer in await this.GetClosestPeersAsync(key, cancel))
            {
                try
                {
                    counterAll++;
                    await this.PutValueToPeerAsync(key, record, peer);
                    counterSuccess++;
                }
                catch (Exception ex)
                {
                    log.Error($"Failed to put to peer {peer.Id}: {ex.Message}");
                }
            }

            // TODO Implement logic to configure the minimum number of peers required
            if (counterSuccess == 0)
            {
                throw new Exception("Unable to put value to any peers");
            }
        }

        private async Task PutValueToPeerAsync(byte[] key, DhtRecordMessage record, Peer peer, CancellationToken cancel = new CancellationToken())
        {
            var message = new DhtMessage
            {
                Type = MessageType.PutValue,
                Key = key,
                Record = record
            };
            using (var stream = await Swarm.DialAsync(peer, this.ToString()))
            {
                ProtoBuf.Serializer.SerializeWithLengthPrefix(stream, message, PrefixStyle.Base128);
                await stream.FlushAsync();

                var response = await ProtoBufHelper.ReadMessageAsync<DhtMessage>(stream, cancel).ConfigureAwait(false);
                if (response.Record.Value.SequenceEqual(record.Value))
                {
                    throw new Exception($"value not put correctly");
                }
            }
        }
    }
}