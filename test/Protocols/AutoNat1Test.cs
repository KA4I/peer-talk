using Ipfs;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace PeerTalk.Protocols
{
    [TestClass]
    public class AutoNat1Test
    {
        [TestMethod]
        public void Protocol_Properties()
        {
            var autonat = new AutoNat1();
            Assert.AreEqual("/libp2p/autonat/1.0.0", autonat.ToString());
            Assert.AreEqual("libp2p/autonat", autonat.Name);
        }

        [TestMethod]
        public void Is_IPeerProtocol()
        {
            var autonat = new AutoNat1();
            Assert.IsInstanceOfType(autonat, typeof(IPeerProtocol));
        }

        [TestMethod]
        public void Registered_In_ProtocolRegistry()
        {
            CollectionAssert.Contains(ProtocolRegistry.Protocols.Keys, "/libp2p/autonat/1.0.0");
        }

        [TestMethod]
        public void Default_Reachability_Is_Unknown()
        {
            var autonat = new AutoNat1();
            Assert.AreEqual(NatStatus.Unknown, autonat.Reachability);
        }

        [TestMethod]
        public void Default_Rate_Limits()
        {
            var autonat = new AutoNat1();
            Assert.AreEqual(30, autonat.GlobalLimit);
            Assert.AreEqual(3, autonat.PeerLimit);
        }
    }
}
