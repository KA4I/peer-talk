using Microsoft.VisualStudio.TestTools.UnitTesting;
using PeerTalk.Multiplex;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace PeerTalk.Protocols
{
    [TestClass]
    public class Yamux1Test
    {
        [TestMethod]
        public void Protocol_Properties()
        {
            var yamux = new Yamux1();
            Assert.AreEqual("/yamux/1.0.0", yamux.ToString());
            Assert.AreEqual("yamux", yamux.Name);
        }

        [TestMethod]
        public void Creates_YamuxMuxer()
        {
            // Yamux1 should be a valid IPeerProtocol
            var yamux = new Yamux1();
            Assert.IsInstanceOfType(yamux, typeof(IPeerProtocol));
        }
    }
}
