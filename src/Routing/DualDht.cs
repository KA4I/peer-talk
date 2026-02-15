using Common.Logging;
using Ipfs;
using Ipfs.CoreApi;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace PeerTalk.Routing
{
    /// <summary>
    ///   Dual DHT that maintains separate WAN and LAN routing tables.
    /// </summary>
    /// <remarks>
    ///   Kubo uses two separate Kademlia DHTs: one for WAN peers (public internet)
    ///   and one for LAN peers (local network). This prevents local peers from
    ///   polluting the WAN routing table and vice versa.
    ///   <para>
    ///   WAN DHT protocol: /ipfs/kad/1.0.0
    ///   LAN DHT protocol: /ipfs/lan/kad/1.0.0
    ///   </para>
    /// </remarks>
    public class DualDht : IService, IPeerRouting, IContentRouting, IValueStore
    {
        static readonly ILog log = LogManager.GetLogger(typeof(DualDht));

        /// <summary>
        ///   The WAN (public internet) DHT instance.
        /// </summary>
        public Dht1 WanDht { get; }

        /// <summary>
        ///   The LAN (local network) DHT instance.
        /// </summary>
        public Dht1 LanDht { get; }

        /// <summary>
        ///   Creates a new Dual DHT with separate WAN and LAN instances.
        /// </summary>
        public DualDht()
        {
            WanDht = new Dht1();
            LanDht = new Dht1 { Name = "ipfs/lan/kad" };
        }

        /// <summary>
        ///   Provides access to other peers.
        /// </summary>
        public Swarm Swarm
        {
            get => WanDht.Swarm;
            set
            {
                WanDht.Swarm = value;
                LanDht.Swarm = value;
            }
        }

        /// <inheritdoc />
        public async Task StartAsync()
        {
            await WanDht.StartAsync().ConfigureAwait(false);
            await LanDht.StartAsync().ConfigureAwait(false);
            log.Debug("Dual DHT started (WAN + LAN)");
        }

        /// <inheritdoc />
        public async Task StopAsync()
        {
            await WanDht.StopAsync().ConfigureAwait(false);
            await LanDht.StopAsync().ConfigureAwait(false);
            log.Debug("Dual DHT stopped");
        }

        /// <inheritdoc />
        public async Task<Peer> FindPeerAsync(MultiHash id, CancellationToken cancel = default)
        {
            // Try LAN first (faster), then WAN
            var lanResult = await LanDht.FindPeerAsync(id, cancel).ConfigureAwait(false);
            if (lanResult != null && lanResult.Addresses.Any())
                return lanResult;

            return await WanDht.FindPeerAsync(id, cancel).ConfigureAwait(false);
        }

        /// <inheritdoc />
        public async Task<IEnumerable<Peer>> FindProvidersAsync(
            Cid id,
            int limit = 20,
            Action<Peer> action = null,
            CancellationToken cancel = default)
        {
            // Query both DHTs and merge results
            var lanProviders = await LanDht.FindProvidersAsync(id, limit, action, cancel).ConfigureAwait(false);
            var remaining = limit - lanProviders.Count();
            if (remaining <= 0)
                return lanProviders.Take(limit);

            var wanProviders = await WanDht.FindProvidersAsync(id, remaining, action, cancel).ConfigureAwait(false);
            return lanProviders.Concat(wanProviders).Take(limit);
        }

        /// <inheritdoc />
        public async Task ProvideAsync(Cid cid, bool advertise = true, CancellationToken cancel = default)
        {
            await WanDht.ProvideAsync(cid, advertise, cancel).ConfigureAwait(false);
            await LanDht.ProvideAsync(cid, advertise, cancel).ConfigureAwait(false);
        }

        /// <inheritdoc />
        public async Task<byte[]> GetAsync(byte[] key, CancellationToken cancel = default)
        {
            // Try LAN first, then WAN
            try
            {
                if (LanDht.TryGetAsync(key, out var lanValue, cancel).Result && lanValue != null)
                    return lanValue;
            }
            catch { /* fall through to WAN */ }

            return await WanDht.GetAsync(key, cancel).ConfigureAwait(false);
        }

        /// <inheritdoc />
        public Task<bool> TryGetAsync(byte[] key, out byte[] value, CancellationToken cancel = default)
        {
            if (LanDht.TryGetAsync(key, out value, cancel).Result)
                return Task.FromResult(true);

            return WanDht.TryGetAsync(key, out value, cancel);
        }

        /// <inheritdoc />
        public async Task PutAsync(byte[] key, byte[] value, CancellationToken cancel = default)
        {
            await WanDht.PutAsync(key, value, cancel).ConfigureAwait(false);
            await LanDht.PutAsync(key, value, cancel).ConfigureAwait(false);
        }

        /// <inheritdoc />
        public Task PutAsync(byte[] key, out byte[] value, CancellationToken cancel = default)
        {
            value = key;
            return PutAsync(key, value, cancel);
        }

        /// <summary>
        ///   Determines if a peer address is a private/LAN address.
        /// </summary>
        public static bool IsPrivateAddress(MultiAddress addr)
        {
            var parts = addr.ToString().Split('/');
            for (int i = 0; i < parts.Length; i++)
            {
                if (parts[i] == "ip4" && i + 1 < parts.Length)
                {
                    var ip = parts[i + 1];
                    if (ip.StartsWith("10.") ||
                        ip.StartsWith("172.16.") || ip.StartsWith("172.17.") || ip.StartsWith("172.18.") ||
                        ip.StartsWith("172.19.") || ip.StartsWith("172.20.") || ip.StartsWith("172.21.") ||
                        ip.StartsWith("172.22.") || ip.StartsWith("172.23.") || ip.StartsWith("172.24.") ||
                        ip.StartsWith("172.25.") || ip.StartsWith("172.26.") || ip.StartsWith("172.27.") ||
                        ip.StartsWith("172.28.") || ip.StartsWith("172.29.") || ip.StartsWith("172.30.") ||
                        ip.StartsWith("172.31.") ||
                        ip.StartsWith("192.168.") ||
                        ip.StartsWith("127.") ||
                        ip == "0.0.0.0")
                        return true;
                }
                if (parts[i] == "ip6" && i + 1 < parts.Length)
                {
                    var ip = parts[i + 1];
                    if (ip == "::1" || ip.StartsWith("fe80") || ip.StartsWith("fd") || ip.StartsWith("fc"))
                        return true;
                }
            }
            return false;
        }
    }
}
