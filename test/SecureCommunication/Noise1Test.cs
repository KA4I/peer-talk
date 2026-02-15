using Ipfs;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PeerTalk.SecureCommunication;
using Semver;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace PeerTalk.Protocols
{
    [TestClass]
    public class Noise1Test
    {
        [TestMethod]
        public void Protocol_Properties()
        {
            var noise = new Noise1();
            Assert.AreEqual("/noise", noise.ToString());
        }

        [TestMethod]
        public void Is_IEncryptionProtocol()
        {
            var noise = new Noise1();
            Assert.IsInstanceOfType(noise, typeof(IEncryptionProtocol));
        }
    }
}
