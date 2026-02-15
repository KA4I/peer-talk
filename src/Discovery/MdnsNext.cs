using Common.Logging;
using Ipfs;
using Makaretu.Dns;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace PeerTalk.Discovery
{
    /// <summary>
    ///   Discovers peers using Multicast DNS according to
    ///   <see href="https://github.com/libp2p/specs/blob/master/discovery/mdns.md"/>
    /// </summary>
    public class MdnsNext : Mdns
    {
        static readonly Random _rng = new();
        string _peerName;

        /// <summary>
        ///   Creates a new instance of the class.  Sets the <see cref="Mdns.ServiceName"/>
        ///   to "_p2p._udp".
        /// </summary>
        public MdnsNext()
        {
            ServiceName = "_p2p._udp";
            // Per the spec, peer-name is a random 32-63 char lowercase alphanumeric string.
            _peerName = RandomPeerName();
        }

        /// <inheritdoc />
        public override ServiceProfile BuildProfile()
        {
            // Filter to LAN-suitable addresses only (ip4/ip6, no relay/WebRTC/loopback).
            var suitableAddresses = LocalPeer.Addresses
                .Where(IsSuitableForMdns)
                .ToArray();
            if (suitableAddresses.Length == 0)
                suitableAddresses = LocalPeer.Addresses.ToArray();

            var profile = new ServiceProfile(
                instanceName: _peerName,
                serviceName: ServiceName,
                port: 0
            );

            // Single TXT record with all dnsaddr= strings (matches Kubo/go-libp2p).
            profile.Resources.RemoveAll(r => r is TXTRecord);
            var txt = new TXTRecord { Name = profile.FullyQualifiedName };
            foreach (var address in suitableAddresses)
            {
                txt.Strings.Add($"dnsaddr={address}");
            }
            profile.Resources.Add(txt);

            return profile;
        }

        /// <inheritdoc />
        public override IEnumerable<MultiAddress> GetAddresses(Message message)
        {
            // Check both AdditionalRecords and Answers for TXT records
            // (different implementations put them in different sections).
            return message.AdditionalRecords.Concat(message.Answers)
                .OfType<TXTRecord>()
                .SelectMany(t => t.Strings)
                .Where(s => s.StartsWith("dnsaddr="))
                .Select(s => s.Substring(8))
                .Select(s => MultiAddress.TryCreate(s))
                .Where(a => a != null);
        }

        /// <summary>
        ///   Determines if a multiaddress is suitable for mDNS advertisement.
        /// </summary>
        static bool IsSuitableForMdns(MultiAddress address)
        {
            var first = address.Protocols.FirstOrDefault();
            if (first == null) return false;

            // Only ip4/ip6 addresses
            if (first.Name != "ip4" && first.Name != "ip6") return false;

            // Skip loopback
            if (IPAddress.TryParse(first.Value, out var ip) && IPAddress.IsLoopback(ip))
                return false;

            // Skip relay and browser transports
            var protocolNames = address.Protocols.Select(p => p.Name).ToHashSet();
            if (protocolNames.Contains("p2p-circuit") ||
                protocolNames.Contains("ws") ||
                protocolNames.Contains("wss") ||
                protocolNames.Contains("webtransport") ||
                protocolNames.Contains("webrtc") ||
                protocolNames.Contains("webrtc-direct"))
                return false;

            return true;
        }

        /// <summary>
        ///   Generates a random peer name per the spec (32-63 lowercase alphanumeric chars).
        /// </summary>
        static string RandomPeerName()
        {
            const string alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
            int length;
            lock (_rng)
            {
                length = 32 + _rng.Next(32);
            }
            var sb = new StringBuilder(length);
            lock (_rng)
            {
                for (int i = 0; i < length; i++)
                    sb.Append(alphabet[_rng.Next(alphabet.Length)]);
            }
            return sb.ToString();
        }

        /// <summary>
        ///   Creates a safe DNS label.
        /// </summary>
        /// <param name="label"></param>
        /// <param name="maxLength"></param>
        /// <returns></returns>
        public static string SafeLabel(string label, int maxLength = 63)
        {
            if (label.Length <= maxLength)
                return label;

            var sb = new StringBuilder();
            while (label.Length > maxLength)
            {
                sb.Append(label.Substring(0, maxLength));
                sb.Append('.');
                label = label.Substring(maxLength);
            }
            sb.Append(label);
            return sb.ToString();
        }

    }
}
