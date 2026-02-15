using Ipfs;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace PeerTalk.Protocols
{
    [TestClass]
    public class IdentifyPush1Test
    {
        [TestMethod]
        public void Protocol_Properties()
        {
            var push = new IdentifyPush1();
            Assert.AreEqual("/ipfs/id/push/1.0.0", push.ToString());
            Assert.AreEqual("ipfs/id/push", push.Name);
        }

        [TestMethod]
        public void Is_IPeerProtocol()
        {
            var push = new IdentifyPush1();
            Assert.IsInstanceOfType(push, typeof(IPeerProtocol));
        }

        [TestMethod]
        public void Registered_In_ProtocolRegistry()
        {
            CollectionAssert.Contains(ProtocolRegistry.Protocols.Keys, "/ipfs/id/push/1.0.0");
        }
    }
}
