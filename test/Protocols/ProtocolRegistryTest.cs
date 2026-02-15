using Ipfs;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace PeerTalk.Protocols
{
    [TestClass]
    public class ProtocolRegistryTest
    {
        [TestMethod]
        public void PreRegistered()
        {
            CollectionAssert.Contains(ProtocolRegistry.Protocols.Keys, "/multistream/1.0.0");
            CollectionAssert.Contains(ProtocolRegistry.Protocols.Keys, "/plaintext/1.0.0");
        }

        [TestMethod]
        public void NewProtocols_Registered()
        {
            CollectionAssert.Contains(ProtocolRegistry.Protocols.Keys, "/noise");
            CollectionAssert.Contains(ProtocolRegistry.Protocols.Keys, "/yamux/1.0.0");
            CollectionAssert.Contains(ProtocolRegistry.Protocols.Keys, "/ipfs/id/push/1.0.0");
            CollectionAssert.Contains(ProtocolRegistry.Protocols.Keys, "/libp2p/autonat/1.0.0");
            CollectionAssert.Contains(ProtocolRegistry.Protocols.Keys, "/libp2p/dcutr");
            CollectionAssert.Contains(ProtocolRegistry.Protocols.Keys, "/libp2p/circuit/relay/0.2.0/hop");
            CollectionAssert.Contains(ProtocolRegistry.Protocols.Keys, "/libp2p/circuit/relay/0.2.0/stop");
        }

    }
}
