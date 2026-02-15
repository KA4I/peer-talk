using Common.Logging;
using Ipfs;
using PeerTalk.Multiplex;
using PeerTalk.Protocols;
using PeerTalk.Transports;
using ProtoBuf;
using Semver;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace PeerTalk.Relay
{
    /// <summary>
    ///   Circuit Relay v2 protocol hop handler.
    /// </summary>
    /// <remarks>
    ///   Protocol: /libp2p/circuit/relay/0.2.0/hop
    ///   See https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md
    /// </remarks>
    public class RelayV2Hop : IPeerProtocol
    {
        static readonly ILog log = LogManager.GetLogger(typeof(RelayV2Hop));

        /// <inheritdoc />
        public string Name { get; } = "libp2p/circuit/relay/0.2.0/hop";

        /// <inheritdoc />
        public SemVersion Version { get; } = new SemVersion(0, 2, 0);

        /// <inheritdoc />
        public override string ToString() => "/libp2p/circuit/relay/0.2.0/hop";

        /// <summary>
        ///   Whether this node acts as a relay (hop) for others.
        /// </summary>
        public bool Enabled { get; set; }

        /// <summary>
        ///   Provides access to the swarm for dialing.
        /// </summary>
        public IDialer Dialer { get; set; }

        /// <summary>
        ///   Maximum duration for a relayed connection in seconds.
        /// </summary>
        public int MaxDurationSeconds { get; set; } = 120;

        /// <summary>
        ///   Maximum bytes that can be relayed.
        /// </summary>
        public long MaxBytes { get; set; } = 1L << 17; // 128 KB

        /// <inheritdoc />
        public async Task ProcessMessageAsync(PeerConnection connection, Stream stream, CancellationToken cancel = default)
        {
            var request = await ProtoBufHelper.ReadMessageAsync<HopMessage>(stream, cancel).ConfigureAwait(false);

            switch (request.Type)
            {
                case HopMessageType.RESERVE:
                    await HandleReserve(request, connection, stream, cancel).ConfigureAwait(false);
                    break;
                case HopMessageType.CONNECT:
                    await HandleConnect(request, connection, stream, cancel).ConfigureAwait(false);
                    break;
                default:
                    await SendStatus(stream, StatusCode.MALFORMED_MESSAGE, cancel).ConfigureAwait(false);
                    break;
            }
        }

        async Task HandleReserve(HopMessage request, PeerConnection connection, Stream stream, CancellationToken cancel)
        {
            if (!Enabled)
            {
                await SendStatus(stream, StatusCode.PERMISSION_DENIED, cancel).ConfigureAwait(false);
                return;
            }

            // Accept reservation
            var response = new HopMessage
            {
                Type = HopMessageType.STATUS,
                Status = StatusCode.OK,
                Reservation = new Reservation
                {
                    ExpireSeconds = (ulong)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600),
                }
            };
            Serializer.SerializeWithLengthPrefix(stream, response, PrefixStyle.Base128);
            await stream.FlushAsync(cancel).ConfigureAwait(false);
        }

        async Task HandleConnect(HopMessage request, PeerConnection connection, Stream srcStream, CancellationToken cancel)
        {
            if (!Enabled)
            {
                await SendStatus(srcStream, StatusCode.PERMISSION_DENIED, cancel).ConfigureAwait(false);
                return;
            }

            if (request.Peer == null || request.Peer.Id == null)
            {
                await SendStatus(srcStream, StatusCode.MALFORMED_MESSAGE, cancel).ConfigureAwait(false);
                return;
            }

            var dstPeerId = new MultiHash(request.Peer.Id);
            try
            {
                var dstPeer = new Peer { Id = dstPeerId };
                var dstStream = await Dialer.DialAsync(dstPeer, "/libp2p/circuit/relay/0.2.0/stop", cancel).ConfigureAwait(false);

                // Send STOP to destination
                var stopMsg = new StopMessage
                {
                    Type = StopMessageType.CONNECT,
                    Peer = new RelayV2Peer
                    {
                        Id = connection.RemotePeer.Id.ToArray(),
                    }
                };
                Serializer.SerializeWithLengthPrefix(dstStream, stopMsg, PrefixStyle.Base128);
                await dstStream.FlushAsync(cancel).ConfigureAwait(false);

                var stopResponse = await ProtoBufHelper.ReadMessageAsync<StopMessage>(dstStream, cancel).ConfigureAwait(false);
                if (stopResponse.Status != StatusCode.OK)
                {
                    await SendStatus(srcStream, StatusCode.NO_RESERVATION, cancel).ConfigureAwait(false);
                    return;
                }

                // Success - tell src
                await SendStatus(srcStream, StatusCode.OK, cancel).ConfigureAwait(false);

                // Pipe src <-> dst with limits
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancel);
                cts.CancelAfter(TimeSpan.FromSeconds(MaxDurationSeconds));

                var srcToDst = PipeAsync(srcStream, dstStream, MaxBytes, cts.Token);
                var dstToSrc = PipeAsync(dstStream, srcStream, MaxBytes, cts.Token);
                await Task.WhenAny(srcToDst, dstToSrc).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                log.Debug($"Relay v2 connect failed: {e.Message}");
                await SendStatus(srcStream, StatusCode.CONNECTION_FAILED, cancel).ConfigureAwait(false);
            }
        }

        static async Task SendStatus(Stream stream, StatusCode status, CancellationToken cancel)
        {
            var msg = new HopMessage { Type = HopMessageType.STATUS, Status = status };
            Serializer.SerializeWithLengthPrefix(stream, msg, PrefixStyle.Base128);
            await stream.FlushAsync(cancel).ConfigureAwait(false);
        }

        static async Task PipeAsync(Stream input, Stream output, long maxBytes, CancellationToken cancel)
        {
            long total = 0;
            var buffer = new byte[4096];
            try
            {
                while (!cancel.IsCancellationRequested)
                {
                    int n = await input.ReadAsync(buffer, 0, buffer.Length, cancel).ConfigureAwait(false);
                    if (n == 0) break;
                    total += n;
                    if (total > maxBytes) break;
                    await output.WriteAsync(buffer, 0, n, cancel).ConfigureAwait(false);
                    await output.FlushAsync(cancel).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) { }
            catch (IOException) { }
        }

        // --- Protobuf messages ---

        enum HopMessageType
        {
            RESERVE = 0,
            CONNECT = 1,
            STATUS = 2,
        }

        enum StopMessageType
        {
            CONNECT = 0,
            STATUS = 1,
        }

        enum StatusCode
        {
            OK = 100,
            RESERVATION_REFUSED = 200,
            RESOURCE_LIMIT_EXCEEDED = 201,
            PERMISSION_DENIED = 202,
            NO_RESERVATION = 203,
            MALFORMED_MESSAGE = 400,
            CONNECTION_FAILED = 500,
        }

        [ProtoContract]
        class HopMessage
        {
            [ProtoMember(1)]
            public HopMessageType Type { get; set; }

            [ProtoMember(2)]
            public RelayV2Peer Peer { get; set; }

            [ProtoMember(3)]
            public Reservation Reservation { get; set; }

            [ProtoMember(4)]
            public Limit Limit { get; set; }

            [ProtoMember(5)]
            public StatusCode Status { get; set; }
        }

        [ProtoContract]
        class StopMessage
        {
            [ProtoMember(1)]
            public StopMessageType Type { get; set; }

            [ProtoMember(2)]
            public RelayV2Peer Peer { get; set; }

            [ProtoMember(3)]
            public Limit Limit { get; set; }

            [ProtoMember(4)]
            public StatusCode Status { get; set; }
        }

        [ProtoContract]
        class RelayV2Peer
        {
            [ProtoMember(1)]
            public byte[] Id { get; set; }

            [ProtoMember(2)]
            public byte[][] Addresses { get; set; }
        }

        [ProtoContract]
        class Reservation
        {
            [ProtoMember(1)]
            public ulong ExpireSeconds { get; set; }

            [ProtoMember(2)]
            public byte[][] Addresses { get; set; }

            [ProtoMember(3)]
            public byte[] Voucher { get; set; }
        }

        [ProtoContract]
        class Limit
        {
            [ProtoMember(1)]
            public uint Duration { get; set; }

            [ProtoMember(2)]
            public ulong Data { get; set; }
        }
    }

    /// <summary>
    ///   Circuit Relay v2 protocol stop handler (target side).
    /// </summary>
    /// <remarks>
    ///   Protocol: /libp2p/circuit/relay/0.2.0/stop
    /// </remarks>
    public class RelayV2Stop : IPeerProtocol
    {
        static readonly ILog log = LogManager.GetLogger(typeof(RelayV2Stop));

        /// <inheritdoc />
        public string Name { get; } = "libp2p/circuit/relay/0.2.0/stop";

        /// <inheritdoc />
        public SemVersion Version { get; } = new SemVersion(0, 2, 0);

        /// <inheritdoc />
        public override string ToString() => "/libp2p/circuit/relay/0.2.0/stop";

        /// <summary>
        ///   Handler invoked when a relayed connection arrives.
        /// </summary>
        public Func<Stream, MultiAddress, MultiAddress, Task> Handler { get; set; }

        /// <inheritdoc />
        public async Task ProcessMessageAsync(PeerConnection connection, Stream stream, CancellationToken cancel = default)
        {
            var request = await ProtoBufHelper.ReadMessageAsync<StopConnectMessage>(stream, cancel).ConfigureAwait(false);

            // Accept the connection
            var response = new StopStatusMessage { Type = 1, Status = 100 }; // STATUS, OK
            Serializer.SerializeWithLengthPrefix(stream, response, PrefixStyle.Base128);
            await stream.FlushAsync(cancel).ConfigureAwait(false);

            if (Handler != null && request.Peer?.Id != null)
            {
                var srcPeerId = new MultiHash(request.Peer.Id);
                var srcAddr = new MultiAddress($"/p2p/{srcPeerId}");
                var dstAddr = connection.LocalAddress ?? new MultiAddress($"/p2p/{connection.LocalPeer.Id}");
                await Handler(stream, dstAddr, srcAddr).ConfigureAwait(false);
            }
        }

        [ProtoContract]
        class StopConnectMessage
        {
            [ProtoMember(1)]
            public int Type { get; set; }

            [ProtoMember(2)]
            public StopPeer Peer { get; set; }
        }

        [ProtoContract]
        class StopPeer
        {
            [ProtoMember(1)]
            public byte[] Id { get; set; }

            [ProtoMember(2)]
            public byte[][] Addresses { get; set; }
        }

        [ProtoContract]
        class StopStatusMessage
        {
            [ProtoMember(1)]
            public int Type { get; set; }

            [ProtoMember(4)]
            public int Status { get; set; }
        }
    }
}
