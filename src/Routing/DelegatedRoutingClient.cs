using Common.Logging;
using Ipfs;
using Ipfs.CoreApi;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace PeerTalk.Routing
{
    /// <summary>
    ///   Delegated Routing client that uses the IPIP-337 HTTP /routing/v1/ API.
    /// </summary>
    /// <remarks>
    ///   Kubo supports delegated routing endpoints (e.g., cid.contact) for
    ///   content routing, peer routing, and IPNS resolution.
    ///   See https://specs.ipfs.tech/routing/http-routing-v1/
    /// </remarks>
    public class DelegatedRoutingClient : IContentRouting, IPeerRouting
    {
        static readonly ILog log = LogManager.GetLogger(typeof(DelegatedRoutingClient));
        readonly HttpClient httpClient;
        readonly Uri baseUrl;

        /// <summary>
        ///   Creates a new delegated routing client.
        /// </summary>
        /// <param name="endpoint">
        ///   The base URL of the delegated routing endpoint (e.g., "https://cid.contact").
        /// </param>
        /// <param name="httpClient">
        ///   Optional HttpClient instance to reuse.
        /// </param>
        public DelegatedRoutingClient(string endpoint, HttpClient httpClient = null)
        {
            this.baseUrl = new Uri(endpoint.TrimEnd('/'));
            this.httpClient = httpClient ?? new HttpClient();
            this.httpClient.DefaultRequestHeaders.Accept.Clear();
            this.httpClient.DefaultRequestHeaders.Accept.Add(
                new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
        }

        /// <inheritdoc />
        public async Task<IEnumerable<Peer>> FindProvidersAsync(
            Cid cid,
            int limit = 20,
            Action<Peer> action = null,
            CancellationToken cancel = default)
        {
            var url = new Uri(baseUrl, $"/routing/v1/providers/{cid}");
            log.Debug($"Delegated FindProviders: {url}");

            var peers = new List<Peer>();
            try
            {
                using var response = await httpClient.GetAsync(url, cancel).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                {
                    log.Debug($"Delegated routing returned {response.StatusCode}");
                    return peers;
                }

                var json = await response.Content.ReadAsStringAsync(cancel).ConfigureAwait(false);
                var doc = JsonDocument.Parse(json);
                var providers = doc.RootElement.GetProperty("Providers");

                foreach (var provider in providers.EnumerateArray())
                {
                    if (peers.Count >= limit) break;

                    try
                    {
                        var peer = ParsePeer(provider);
                        if (peer != null)
                        {
                            peers.Add(peer);
                            action?.Invoke(peer);
                        }
                    }
                    catch (Exception e)
                    {
                        log.Debug($"Failed to parse provider: {e.Message}");
                    }
                }
            }
            catch (Exception e)
            {
                log.Debug($"Delegated FindProviders failed: {e.Message}");
            }

            return peers;
        }

        /// <inheritdoc />
        public Task ProvideAsync(Cid cid, bool advertise = true, CancellationToken cancel = default)
        {
            // Delegated routing clients typically don't publish provides
            // (that's done by the node's own DHT)
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public async Task<Peer> FindPeerAsync(MultiHash id, CancellationToken cancel = default)
        {
            var url = new Uri(baseUrl, $"/routing/v1/peers/{id}");
            log.Debug($"Delegated FindPeer: {url}");

            try
            {
                using var response = await httpClient.GetAsync(url, cancel).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                    return null;

                var json = await response.Content.ReadAsStringAsync(cancel).ConfigureAwait(false);
                var doc = JsonDocument.Parse(json);
                var peers = doc.RootElement.GetProperty("Peers");

                foreach (var peerElement in peers.EnumerateArray())
                {
                    var peer = ParsePeer(peerElement);
                    if (peer != null && peer.Id == id)
                        return peer;
                }
            }
            catch (Exception e)
            {
                log.Debug($"Delegated FindPeer failed: {e.Message}");
            }

            return null;
        }

        /// <summary>
        ///   Gets an IPNS record from the delegated routing endpoint.
        /// </summary>
        public async Task<byte[]> GetIpnsAsync(MultiHash peerId, CancellationToken cancel = default)
        {
            var url = new Uri(baseUrl, $"/routing/v1/ipns/{peerId}");
            log.Debug($"Delegated GetIPNS: {url}");

            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.Accept.Clear();
                request.Headers.Accept.Add(
                    new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/vnd.ipfs.ipns-record"));

                using var response = await httpClient.SendAsync(request, cancel).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                    return null;

                return await response.Content.ReadAsByteArrayAsync(cancel).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                log.Debug($"Delegated GetIPNS failed: {e.Message}");
                return null;
            }
        }

        /// <summary>
        ///   Publishes an IPNS record via the delegated routing endpoint.
        /// </summary>
        public async Task PutIpnsAsync(MultiHash peerId, byte[] record, CancellationToken cancel = default)
        {
            var url = new Uri(baseUrl, $"/routing/v1/ipns/{peerId}");
            log.Debug($"Delegated PutIPNS: {url}");

            try
            {
                var content = new ByteArrayContent(record);
                content.Headers.ContentType =
                    new System.Net.Http.Headers.MediaTypeHeaderValue("application/vnd.ipfs.ipns-record");

                using var response = await httpClient.PutAsync(url, content, cancel).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                {
                    log.Debug($"Delegated PutIPNS returned {response.StatusCode}");
                }
            }
            catch (Exception e)
            {
                log.Debug($"Delegated PutIPNS failed: {e.Message}");
            }
        }

        static Peer ParsePeer(JsonElement element)
        {
            if (!element.TryGetProperty("ID", out var idElement))
                return null;

            var idStr = idElement.GetString();
            if (string.IsNullOrEmpty(idStr))
                return null;

            var peer = new Peer { Id = idStr };

            if (element.TryGetProperty("Addrs", out var addrs))
            {
                var addresses = new List<MultiAddress>();
                foreach (var addr in addrs.EnumerateArray())
                {
                    var addrStr = addr.GetString();
                    if (!string.IsNullOrEmpty(addrStr))
                    {
                        try { addresses.Add(new MultiAddress(addrStr)); }
                        catch { /* skip invalid addresses */ }
                    }
                }
                peer.Addresses = addresses;
            }

            return peer;
        }
    }
}
