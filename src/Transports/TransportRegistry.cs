using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
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
            Register("ws", () => new Ws());
            Register("wss", () => new Ws());
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS() || OperatingSystem.IsWindows() || OperatingSystem.IsAndroid())
            {
#pragma warning disable CA1416 // Platform guard is above; lambda defers instantiation
                if (QuicTransport.IsSupported)
                    Register("quic-v1", () => new QuicTransport());
#pragma warning restore CA1416
            }
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
