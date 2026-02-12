using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PeerTalk.Transports
{
    class TransportRegistry
    {
        public Dictionary<string, Func<IPeerTransport>> Transports;

        public TransportRegistry()
        {
            Transports = new Dictionary<string, Func<IPeerTransport>>();
            Register("tcp", () => new Tcp());
            Register("udp", () => new Udp());
        }

        public void Register(string protocolName, Func<IPeerTransport> transport)
        {
            if (Transports.ContainsKey(protocolName))
            {
                throw new ArgumentException($"A protocol is already registered for {protocolName}");
            }

            Transports.Add(protocolName, transport);
        }

        public void Deregister(string protocolName)
        {
            Transports.Remove(protocolName);
        }

    }
}
