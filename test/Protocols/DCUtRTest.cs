using Ipfs;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace PeerTalk.Protocols
{
    [TestClass]
    public class DCUtRTest
    {
        [TestMethod]
        public void Protocol_Properties()
        {
            var dcutr = new DCUtR();
            Assert.AreEqual("/libp2p/dcutr", dcutr.ToString());
            Assert.AreEqual("libp2p/dcutr", dcutr.Name);
        }

        [TestMethod]
        public void Is_IPeerProtocol()
        {
            var dcutr = new DCUtR();
            Assert.IsInstanceOfType(dcutr, typeof(IPeerProtocol));
        }

        [TestMethod]
        public void Registered_In_ProtocolRegistry()
        {
            // DCUtR uses versionless name /libp2p/dcutr
            CollectionAssert.Contains(ProtocolRegistry.Protocols.Keys, "/libp2p/dcutr");
        }
    }
}
