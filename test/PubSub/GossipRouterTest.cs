using Ipfs;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PeerTalk.PubSub;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace PeerTalk.PubSub
{
    [TestClass]
    public class GossipRouterTest
    {
        [TestMethod]
        public void Protocol_Properties()
        {
            var gossip = new GossipRouter();
            Assert.AreEqual("/meshsub/1.2.0", gossip.ToString());
        }

        [TestMethod]
        public void Is_IMessageRouter()
        {
            var gossip = new GossipRouter();
            Assert.IsInstanceOfType(gossip, typeof(IMessageRouter));
        }

        [TestMethod]
        public async Task Join_And_Leave_Topic()
        {
            var gossip = new GossipRouter();
            await gossip.JoinTopicAsync("test-topic", CancellationToken.None);

            // After joining, topic should be tracked internally
            // LeaveTopicAsync should not throw
            await gossip.LeaveTopicAsync("test-topic", CancellationToken.None);
        }

        [TestMethod]
        public void RemoteSubscriptions()
        {
            var gossip = new GossipRouter();

            var sub = new Subscription { Topic = "topic", Subscribe = true };
            var peer = new Peer { Id = "QmXK9VBxaXFuuT29AaPUTgW3jBWZ9JgLVZYdMYTHC6LLAH" };
            gossip.ProcessSubscription(sub, peer);
            Assert.AreEqual(1, gossip.RemoteTopics.GetPeers("topic").Count());

            var unsub = new Subscription { Topic = "topic", Subscribe = false };
            gossip.ProcessSubscription(unsub, peer);
            Assert.AreEqual(0, gossip.RemoteTopics.GetPeers("topic").Count());
        }
    }
}
