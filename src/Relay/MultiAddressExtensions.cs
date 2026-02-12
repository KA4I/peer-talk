using System;
using System.IO;
using System.Linq;
using Ipfs;

namespace PeerTalk.Relay
{
    /// <summary>
    /// MultiAddress extensions for relay specific code
    /// </summary>
    static class MultiAddressExtensions
    {
        /// <summary>
        /// Parse a p2p-circuit address in to the relay and destination specific parts
        /// </summary>
        /// <param name="p2PCircuitAddress"></param>
        /// <returns></returns>
        public static P2PCircuitMultiAddress ToP2PCircuitMultiAddress(this MultiAddress p2PCircuitAddress)
        {
            if (p2PCircuitAddress.Protocols.Count < 2)
            {
                throw new InvalidDataException("A p2p circuit address must contain at least /p2p-circuit/ and the destination peer id");
            }

            var p2pCircuitString = p2PCircuitAddress.ToString();
            var p2pParts = p2pCircuitString.Split(new[] {"/p2p-circuit"}, StringSplitOptions.RemoveEmptyEntries);
            var destinationAddress = p2pParts.Last();
            var relayAddress = p2pParts.Length > 1 ? p2pParts.First() : null;
            return new P2PCircuitMultiAddress
            {
                RelayAddress = relayAddress != null ? new MultiAddress(relayAddress) : null,
                DestinationAddress = new MultiAddress(destinationAddress)
            };
        }

        public static bool IsP2PCircuitAddress(this MultiAddress address)
        {
            return address.Protocols.Any(p => p.Code == 290);
        }
    }

    class P2PCircuitMultiAddress
    {
        public MultiAddress RelayAddress { get; set; }

        public MultiAddress DestinationAddress { get; set; }
    }
}