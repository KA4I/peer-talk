using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Ipfs;

namespace PeerTalk.Relay
{
    /// <summary>
    /// Contains a collection of addresses for peers that provide relay
    /// </summary>
    public class RelayCollection
    {
        private readonly ConcurrentDictionary<MultiAddress, object> relayAddresses = new ConcurrentDictionary<MultiAddress, object>();

        /// <summary>
        /// Get the list of known relay addresses
        /// </summary>
        public IEnumerable<MultiAddress> RelayAddresses => new ReadOnlyCollection<MultiAddress>(relayAddresses.Keys.ToList());

        /// <summary>
        /// Add a new address to the relay collection
        /// </summary>
        /// <param name="relayAddress"></param>
        /// <returns></returns>
        public bool Add(MultiAddress relayAddress)
        {
            return relayAddresses.TryAdd(relayAddress, relayAddress);
        }

        /// <summary>
        /// Remove an address from the relay collection
        /// </summary>
        /// <param name="relayAddress"></param>
        /// <returns></returns>
        public bool Remove(MultiAddress relayAddress)
        {
            return relayAddresses.TryRemove(relayAddress, out var _);
        }

        private static Lazy<RelayCollection> defaultCollection = new Lazy<RelayCollection>(() =>
        {
            var relayCollection = new RelayCollection();
            relayCollection.Add(
                new MultiAddress("/ip4/147.75.80.110/tcp/4001/p2p/QmbFgm5zan8P6eWWmeyfncR5feYEMPbht5b1FW1C37aQ7y"));
            relayCollection.Add(
                new MultiAddress("/ip4/147.75.195.153/tcp/4001/p2p/QmW9m57aiBDHAkKj9nmFSEn7ZqrcF1fZS4bipsTCHburei"));
            relayCollection.Add(
                new MultiAddress("/ip4/147.75.70.221/tcp/4001/p2p/Qme8g49gm3q4Acp7xWBKg3nAa9fxZ1YmyDJdyGgoG6LsXh"));
            return relayCollection;
        });

        /// <summary>
        /// Get the default protocol labs set of relays
        /// </summary>
        /// <remarks>See https://github.com/libp2p/go-libp2p/blob/master/p2p/host/relay/autorelay.go </remarks>
        public static RelayCollection Default => defaultCollection.Value;
    }
}