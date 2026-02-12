using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Ipfs;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Nerdbank.Streams;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using PeerTalk.Cryptography;
using PeerTalk.Protocols;
using PeerTalk.SecureCommunication;
using PeerTalk.Transports;
using ProtoBuf;
using Serilog;
using Serilog.Formatting.Compact;

namespace PeerTalk.Relay
{
    [TestClass]
    public class RelayTests
    {
        [AssemblyInitialize]
        public static void AssemblyInitialize(TestContext context)
        {
            var log = new LoggerConfiguration()
                .WriteTo.File(new CompactJsonFormatter(),
                    @"C:\repos\peer-talk\log.txt",
                    flushToDiskInterval: TimeSpan.FromSeconds(1),
                    rollingInterval: RollingInterval.Day)
                .MinimumLevel.Verbose()
                .Enrich.WithThreadId()
                .CreateLogger();

            // set global instance of Serilog logger which Common.Logger.Serilog requires.
            Log.Logger = log;
        }

        [TestMethod]
        public async Task JustTestRelay()
        {
            var localKey = CryptoHelpers.GetKey();
            var localId = localKey.Public.CreateKeyId();
            var localPeer = new Peer
            {
                Id = localId,
                PublicKey = localKey.CreatePublicKey(),
                Addresses = new MultiAddress[]
                    {$"/ip4/0.0.0.0/tcp/4001/p2p/{localId}"}
            };
            var mockLocalDialer = new MockDialer
            {
                LocalPeer = localPeer
            };
            var localPeerRelay = new Relay()
            {
                Dialer = mockLocalDialer
            };

            var relayKey = CryptoHelpers.GetKey();
            var relayId = relayKey.Public.CreateKeyId();
            var relayPeer = new Peer
            {
                Id = relayId,
                PublicKey = relayKey.CreatePublicKey(),
                Addresses = new MultiAddress[]
                    {$"/ip4/0.0.0.0/tcp/4002/p2p/{relayId}"}
            };
            var mockRelayDialer = new MockDialer
            {
                LocalPeer = relayPeer
            };
            var hopRelay = new Relay()
            {
                Hop = true,
                Dialer = mockRelayDialer
            };

            var remoteKey = CryptoHelpers.GetKey();
            var remoteId = remoteKey.Public.CreateKeyId();
            var remotePeer = new Peer
            {
                Id = remoteId,
                PublicKey = remoteKey.CreatePublicKey(),
                Addresses = new MultiAddress[]
                    {$"/ip4/0.0.0.0/tcp/4003/p2p/{remoteId}"}
            };
            var remoteDialer = new MockDialer
            {
                LocalPeer = remotePeer
            };
            var remotePeerRelay = new Relay
            {
                Dialer = remoteDialer
            };

            var localToRelayConnection = FullDuplexStream.CreatePair();
            var localToRelayPeerConnection = new PeerConnection
            {
                IsIncoming = false,
                Stream = localToRelayConnection.Item1,
                LocalPeer = localPeer,
                RemotePeer = relayPeer,
                LocalPeerKey = Key.CreatePrivateKey(localKey.Private)
            };

            var relayFromLocalPeerConnection = new PeerConnection
            {
                IsIncoming = true,
                Stream = localToRelayConnection.Item2,
                LocalPeer = relayPeer,
                RemotePeer = localPeer,
                LocalPeerKey = Key.CreatePrivateKey(relayKey.Private)
            };

            var remoteToRelayConnection = FullDuplexStream.CreatePair();
            var remoteToRelayPeerConnection = new PeerConnection
            {
                IsIncoming = false,
                Stream = remoteToRelayConnection.Item1,
                LocalPeer = remotePeer,
                RemotePeer = relayPeer,
                LocalPeerKey = Key.CreatePrivateKey(remoteKey.Private)
            };
            var relayFromRemotePeerConnection = new PeerConnection()
            {
                IsIncoming = true,
                Stream = remoteToRelayConnection.Item2,
                LocalPeer = relayPeer,
                RemotePeer = remotePeer,
                LocalPeerKey = Key.CreatePrivateKey(relayKey.Private)
            };

            mockLocalDialer.AddConnection(
                relayPeer.Addresses.First(), 
                localToRelayPeerConnection);
            mockRelayDialer.AddConnection(
                remotePeer.Addresses.First(),
                relayFromRemotePeerConnection);

            remotePeerRelay.Listen(remotePeer.Addresses.First(),
                (stream, localAddress, remoteAddress) =>
                {
                    Task.Run(() =>
                    {
                        // echo
                        byte[] buffer = new byte[1024];
                        var read = stream.Read(buffer, 0, 1024);
                        var request = Encoding.UTF8.GetString(buffer, 0, read);
                        buffer = Encoding.UTF8.GetBytes(request + " back");
                        stream.Write(buffer, 0, buffer.Length);
                        stream.Flush();
                    });
                    return Task.CompletedTask;
                }, CancellationToken.None);
            
            var remoteRelayAddress = new MultiAddress($"{relayPeer.Addresses.First()}/p2p-circuit/p2p/{remotePeer.Id}");
            var relayCancellationTokenSource = new CancellationTokenSource();
            var relayTask = Task.Run(() =>
                hopRelay.ProcessMessageAsync(relayFromLocalPeerConnection, relayFromLocalPeerConnection.Stream, relayCancellationTokenSource.Token));
            var connectTask = Task.Run(async () =>
            {
                var connection = await localPeerRelay.ConnectAsync(remoteRelayAddress);
                var hello = Encoding.UTF8.GetBytes("Hello");
                connection.Write(hello, 0, hello.Length);
                connection.Flush();
                var response = new byte[1024];
                var read = connection.Read(response, 0, 1024);
                Assert.AreEqual("Hello back", Encoding.UTF8.GetString(response.AsSpan().Slice(0, read).ToArray()));
            });
            var stopTask = Task.Run(() =>
                remotePeerRelay.ProcessMessageAsync(remoteToRelayPeerConnection, remoteToRelayPeerConnection.Stream));

            await stopTask;
            await connectTask;
            relayCancellationTokenSource.Cancel();
            await relayTask;
        }

        class MockDialer : IDialer
        {
            IDictionary<MultiAddress, PeerConnection> connections = new Dictionary<MultiAddress, PeerConnection>();

            public void AddConnection(MultiAddress address, PeerConnection peerConnection)
            {
                if (connections.ContainsKey(address))
                {
                    throw new ArgumentException();
                }

                connections.Add(address, peerConnection);
            }

            public Task<PeerConnection> ConnectAsync(MultiAddress address, CancellationToken cancel = default(CancellationToken))
            {
                if (!connections.TryGetValue(address, out var connection))
                {
                    throw new ArgumentOutOfRangeException();
                }

                return Task.FromResult(connection);
            }

            public Task<PeerConnection> ConnectAsync(Peer peer, CancellationToken cancel = default(CancellationToken))
            {
                throw new NotImplementedException();
            }

            public Task<Stream> DialAsync(Peer peer, string protocol, CancellationToken cancel = default(CancellationToken))
            {
                foreach (var peerConnection in connections.Values)
                {
                    if (peerConnection.RemotePeer == peer)
                    {
                        return Task.FromResult(peerConnection.Stream);
                    }
                }

                throw new ArgumentException();
            }

            public void AddProtocol(IPeerProtocol protocol)
            {
                
            }

            public Peer LocalPeer { get; set; }
        }
        
        [TestMethod]
        public async Task TestEndToEnd()
        {
            var localKey = CryptoHelpers.GetKey();
            var localId = localKey.Public.CreateKeyId();
            var localPeer = new Peer
            {
                Id = localId,
                PublicKey = localKey.CreatePublicKey()
            };

            var relayKey = CryptoHelpers.GetKey();
            var relayId = relayKey.Public.CreateKeyId();
            var relayPeer = new Peer
            {
                Id = relayId,
                PublicKey = relayKey.CreatePublicKey()
            };

            var remoteKey = CryptoHelpers.GetKey();
            var remoteId = remoteKey.Public.CreateKeyId();
            var remotePeer = new Peer
            {
                Id = remoteId,
                PublicKey = remoteKey.CreatePublicKey()
            };

            var localSwarm = new Swarm()
            {
                LocalPeer = localPeer,
                LocalPeerKey = Key.CreatePrivateKey(localKey.Private)
            };
            var remoteSwarm = new Swarm()
            {
                LocalPeer = remotePeer,
                LocalPeerKey = Key.CreatePrivateKey(remoteKey.Private)
            };
            var relaySwarm = new Swarm()
            {
                LocalPeer = relayPeer,
                LocalPeerKey = Key.CreatePrivateKey(relayKey.Private)
            };

            var pingA = new Ping1 { Swarm = localSwarm };
            await pingA.StartAsync();
            var pingB = new Ping1() { Swarm = remoteSwarm };
            await pingB.StartAsync();

            // for debugging
            localSwarm.TransportConnectionTimeout = TimeSpan.FromHours(1);
            remoteSwarm.TransportConnectionTimeout = TimeSpan.FromHours(1);
            relaySwarm.TransportConnectionTimeout = TimeSpan.FromHours(1);

            // switch to fake tcp
            SwapToFakeTcp(localSwarm);
            SwapToFakeTcp(remoteSwarm);
            SwapToFakeTcp(relaySwarm);

            await localSwarm.StartAsync();
            await remoteSwarm.StartAsync();
            await relaySwarm.StartAsync();

            await localSwarm.StartListeningAsync("/ip4/0.0.0.0/tcp/4001");
            await remoteSwarm.StartListeningAsync("/ip4/0.0.0.0/tcp/4002");
            await relaySwarm.StartListeningAsync("/ip4/0.0.0.0/tcp/4003");

            var relayCollection = new RelayCollection();
            relayCollection.Add(relayPeer.Addresses.First(a => a.Protocols.Any(p => p.Name == "tcp")));
            localSwarm.EnableRelay(relayCollection);
            remoteSwarm.EnableRelay(relayCollection);
            relaySwarm.EnableRelay(relayCollection, hop: true);
            //await swarmA.StartListeningAsync("/p2p-circuit");
            await remoteSwarm.StartListeningAsync("/p2p-circuit");
            await relaySwarm.StartListeningAsync("/p2p-circuit");

            // set up connection from remote to the relay
            var bRelayConn = await remoteSwarm.ConnectAsync(relayCollection.RelayAddresses.First());

            // connect to remote through swarm
            var connectionToBThroughRelay = await localSwarm.ConnectAsync(new MultiAddress($"/p2p-circuit/p2p/{remotePeer.Id}"));
            Assert.IsNotNull(connectionToBThroughRelay);

            var response = await pingA.PingAsync(remotePeer.Id);
            Assert.IsTrue(response.All(p => p.Success));


            void SwapToFakeTcp(Swarm swarm)
            {
                swarm.DeregisterTransport("tcp");
                swarm.RegisterTransport("tcp", () => new FakeTcpTransport());
            }
        }

        class FakeTcpTransport : IPeerTransport
        {
            public Task<Stream> ConnectAsync(MultiAddress address, CancellationToken cancel = default(CancellationToken))
            {
                if (!listeners.TryGetValue(GetPort(address), out var handler))
                {
                    return null;
                }

                var streamPair = FullDuplexStream.CreatePair();
                handler(streamPair.Item2, myAddress, address);
                return Task.FromResult(streamPair.Item1);
            }

            /// <summary>
            /// port to handler lookup, as we listen on different ports for different peers
            /// </summary>
            private static Dictionary<int, Func<Stream, MultiAddress, MultiAddress, Task>> listeners = new Dictionary<int, Func<Stream, MultiAddress, MultiAddress, Task>>();
            private MultiAddress myAddress;

            public MultiAddress Listen(MultiAddress address, Func<Stream, MultiAddress, MultiAddress, Task> handler, CancellationToken cancel)
            {
                this.myAddress = address;
                listeners.Add(GetPort(address), handler);
                return address;
            }

            private static int GetPort(MultiAddress address)
            {
                return int.Parse(address.Protocols.First(p => p.Name == "tcp").Value);
            }
        }
    }
}