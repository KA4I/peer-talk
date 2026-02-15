using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeerTalk.PubSub;
using PeerTalk.Relay;
using PeerTalk.SecureCommunication;
using PeerTalk.Transports;

namespace PeerTalk.Protocols
{
    /// <summary>
    ///   Metadata on <see cref="IPeerProtocol"/>.
    /// </summary>
    public static class ProtocolRegistry
    {
        /// <summary>
        ///   All the peer protocols.
        /// </summary>
        /// <remarks>
        ///   The key is the name and version of the peer protocol, like "/multiselect/1.0.0".
        ///   The value is a Func that returns an new instance of the peer protocol.
        /// </remarks>
        public static Dictionary<string, Func<IPeerProtocol>> Protocols;

        static ProtocolRegistry()
        {
            Protocols = new Dictionary<string, Func<IPeerProtocol>>();
            Register<Multistream1>();
            Register<SecureCommunication.Tls1>();
            Register<SecureCommunication.Noise1>();
            Register<Plaintext1>();
            Register<Identify1>();
            Register<IdentifyPush1>();
            Register<IdentifyDelta1>();
            Register<Yamux1>();
            Register<Mplex67>();
            Register<RelayV2Hop>();
            Register<RelayV2Stop>();
            Register<AutoNat1>();
            Register<AutoNat2>();
            Register<DCUtR>();
        }

        /// <summary>
        ///   Register a new protocol.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        public static void Register<T>() where T: IPeerProtocol, new()
        {
            var p = new T();
            Protocols.Add(p.ToString(), () => new T());
        }

        /// <summary>
        ///   Remove the specified protocol.
        /// </summary>
        /// <param name="protocolName">
        ///   The protocol name to remove.
        /// </param>
        public static void Deregister(string protocolName)
        {
            Protocols.Remove(protocolName);
        }

    }
}
