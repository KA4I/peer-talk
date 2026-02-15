using Common.Logging;
using Nito.AsyncEx;
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PeerTalk.Multiplex
{
    /// <summary>
    ///   Yamux stream multiplexer.
    /// </summary>
    /// <remarks>
    ///   See https://github.com/hashicorp/yamux/blob/master/spec.md
    ///   Header: [version(1) | type(1) | flags(2) | streamID(4) | length(4)] = 12 bytes, big-endian.
    /// </remarks>
    public class YamuxMuxer : IMuxer
    {
        static readonly ILog log = LogManager.GetLogger(typeof(YamuxMuxer));

        const byte Version = 0;
        const int HeaderSize = 12;

        // Types
        const byte TypeData = 0;
        const byte TypeWindowUpdate = 1;
        const byte TypePing = 2;
        const byte TypeGoAway = 3;

        // Flags
        const ushort FlagSYN = 1;
        const ushort FlagACK = 2;
        const ushort FlagFIN = 4;
        const ushort FlagRST = 8;

        // Default initial window size per the spec: 256 KB
        const int InitialWindowSize = 256 * 1024;

        uint nextStreamId;
        readonly AsyncLock channelWriteLock = new AsyncLock();
        readonly ConcurrentDictionary<uint, YamuxSubstream> substreams = new ConcurrentDictionary<uint, YamuxSubstream>();

        /// <summary>
        ///   Creates a Yamux muxer.
        /// </summary>
        /// <param name="initiator">True if this side initiated the connection.</param>
        public YamuxMuxer(bool initiator)
        {
            // Initiator uses odd stream IDs, responder uses even
            nextStreamId = initiator ? 1u : 2u;
        }

        /// <inheritdoc />
        public PeerConnection Connection { get; set; }

        /// <inheritdoc />
        public Stream Channel { get; set; }

        /// <inheritdoc />
        public event EventHandler<Substream> SubstreamCreated;

        /// <inheritdoc />
        public event EventHandler<Substream> SubstreamClosed;

        /// <inheritdoc />
        public async Task<Substream> CreateStreamAsync(string name = "", CancellationToken cancel = default)
        {
            var streamId = nextStreamId;
            nextStreamId += 2;

            var substream = new YamuxSubstream(streamId, this, name);
            substreams.TryAdd(streamId, substream);

            // Send SYN
            await WriteHeaderAsync(TypeWindowUpdate, FlagSYN, streamId, InitialWindowSize, cancel).ConfigureAwait(false);

            return substream.AsSubstream();
        }

        /// <inheritdoc />
        public async Task<Substream> RemoveStreamAsync(Substream stream, CancellationToken cancel = default)
        {
            if (stream is YamuxSubstreamAdapter adapter)
            {
                var yamuxStream = adapter.Inner;
                if (substreams.TryRemove(yamuxStream.StreamId, out _))
                {
                    await WriteHeaderAsync(TypeWindowUpdate, FlagFIN, yamuxStream.StreamId, 0, cancel).ConfigureAwait(false);
                }
            }
            return stream;
        }

        /// <inheritdoc />
        public Task<IDisposable> AcquireWriteAccessAsync() => channelWriteLock.LockAsync();

        /// <inheritdoc />
        public async Task ProcessRequestsAsync(CancellationToken cancel = default)
        {
            try
            {
                var headerBuf = new byte[HeaderSize];
                while (Channel.CanRead && !cancel.IsCancellationRequested)
                {
                    if (!await ReadExactAsync(Channel, headerBuf, 0, HeaderSize, cancel).ConfigureAwait(false))
                        break;

                    byte version = headerBuf[0];
                    byte type = headerBuf[1];
                    ushort flags = (ushort)((headerBuf[2] << 8) | headerBuf[3]);
                    uint streamId = (uint)((headerBuf[4] << 24) | (headerBuf[5] << 16) | (headerBuf[6] << 8) | headerBuf[7]);
                    uint length = (uint)((headerBuf[8] << 24) | (headerBuf[9] << 16) | (headerBuf[10] << 8) | headerBuf[11]);

                    if (version != Version)
                    {
                        log.Warn($"Yamux: unexpected version {version}");
                    }

                    switch (type)
                    {
                        case TypeData:
                            await HandleData(streamId, flags, length, cancel).ConfigureAwait(false);
                            break;
                        case TypeWindowUpdate:
                            HandleWindowUpdate(streamId, flags, length);
                            break;
                        case TypePing:
                            await HandlePing(flags, length, cancel).ConfigureAwait(false);
                            break;
                        case TypeGoAway:
                            log.Debug($"Yamux: received GoAway code={length}");
                            return;
                        default:
                            log.Warn($"Yamux: unknown type {type}");
                            break;
                    }
                }
            }
            catch (EndOfStreamException) { }
            catch (IOException) { }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionReset) { }
            catch (Exception) when (cancel.IsCancellationRequested) { }
            catch (Exception e)
            {
                if (Channel.CanRead || Channel.CanWrite)
                    log.Error("Yamux: processing failed", e);
            }

            Connection?.Dispose();
            foreach (var s in substreams.Values.ToArray())
            {
                s.NoMoreData();
            }
            substreams.Clear();
        }

        async Task HandleData(uint streamId, ushort flags, uint length, CancellationToken cancel)
        {
            if ((flags & FlagSYN) != 0)
            {
                CreateIncoming(streamId);
            }

            if (length > 0)
            {
                var payload = new byte[length];
                await ReadExactForceAsync(Channel, payload, 0, (int)length, cancel).ConfigureAwait(false);

                if (substreams.TryGetValue(streamId, out var sub))
                {
                    sub.AddData(payload);
                    // Send window update asynchronously so we don't block the read loop
                    _ = WriteHeaderAsync(TypeWindowUpdate, 0, streamId, length, cancel);
                }
            }

            if ((flags & FlagFIN) != 0 || (flags & FlagRST) != 0)
            {
                if (substreams.TryRemove(streamId, out var sub))
                {
                    sub.NoMoreData();
                    SubstreamClosed?.Invoke(this, sub.AsSubstream());
                }
            }
        }

        void HandleWindowUpdate(uint streamId, ushort flags, uint length)
        {
            if ((flags & FlagSYN) != 0)
            {
                CreateIncoming(streamId);
                // Send ACK
                _ = WriteHeaderAsync(TypeWindowUpdate, FlagACK, streamId, InitialWindowSize, default);
            }

            if (substreams.TryGetValue(streamId, out var sub))
            {
                sub.AddWindowCredit((int)length);
            }

            if ((flags & FlagFIN) != 0 || (flags & FlagRST) != 0)
            {
                if (substreams.TryRemove(streamId, out var s))
                {
                    s.NoMoreData();
                    SubstreamClosed?.Invoke(this, s.AsSubstream());
                }
            }
        }

        async Task HandlePing(ushort flags, uint opaque, CancellationToken cancel)
        {
            if ((flags & FlagSYN) != 0)
            {
                // Respond with pong (ACK + same opaque)
                await WriteHeaderAsync(TypePing, FlagACK, 0, opaque, cancel).ConfigureAwait(false);
            }
        }

        void CreateIncoming(uint streamId)
        {
            if (substreams.ContainsKey(streamId))
                return;

            var sub = new YamuxSubstream(streamId, this, "");
            if (substreams.TryAdd(streamId, sub))
            {
                SubstreamCreated?.Invoke(this, sub.AsSubstream());
            }
        }

        internal async Task WriteHeaderAsync(byte type, ushort flags, uint streamId, uint length, CancellationToken cancel)
        {
            var header = new byte[HeaderSize];
            header[0] = Version;
            header[1] = type;
            header[2] = (byte)(flags >> 8);
            header[3] = (byte)flags;
            header[4] = (byte)(streamId >> 24);
            header[5] = (byte)(streamId >> 16);
            header[6] = (byte)(streamId >> 8);
            header[7] = (byte)streamId;
            header[8] = (byte)(length >> 24);
            header[9] = (byte)(length >> 16);
            header[10] = (byte)(length >> 8);
            header[11] = (byte)length;

            using (await channelWriteLock.LockAsync(cancel).ConfigureAwait(false))
            {
                await Channel.WriteAsync(header, 0, HeaderSize, cancel).ConfigureAwait(false);
                await Channel.FlushAsync(cancel).ConfigureAwait(false);
            }
        }

        internal async Task WriteDataAsync(uint streamId, byte[] data, int offset, int count, CancellationToken cancel)
        {
            var header = new byte[HeaderSize];
            header[0] = Version;
            header[1] = TypeData;
            // flags = 0
            header[4] = (byte)(streamId >> 24);
            header[5] = (byte)(streamId >> 16);
            header[6] = (byte)(streamId >> 8);
            header[7] = (byte)streamId;
            header[8] = (byte)(count >> 24);
            header[9] = (byte)(count >> 16);
            header[10] = (byte)(count >> 8);
            header[11] = (byte)count;

            using (await channelWriteLock.LockAsync(cancel).ConfigureAwait(false))
            {
                await Channel.WriteAsync(header, 0, HeaderSize, cancel).ConfigureAwait(false);
                await Channel.WriteAsync(data, offset, count, cancel).ConfigureAwait(false);
                await Channel.FlushAsync(cancel).ConfigureAwait(false);
            }
        }

        static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer, int offset, int count, CancellationToken cancel)
        {
            int total = 0;
            while (total < count)
            {
                int n = await stream.ReadAsync(buffer, offset + total, count - total, cancel).ConfigureAwait(false);
                if (n == 0) return false;
                total += n;
            }
            return true;
        }

        static async Task ReadExactForceAsync(Stream stream, byte[] buffer, int offset, int count, CancellationToken cancel)
        {
            int total = 0;
            while (total < count)
            {
                int n = await stream.ReadAsync(buffer, offset + total, count - total, cancel).ConfigureAwait(false);
                if (n == 0) throw new EndOfStreamException();
                total += n;
            }
        }
    }

    /// <summary>
    ///   Internal yamux per-stream state.
    /// </summary>
    internal class YamuxSubstream
    {
        readonly YamuxMuxer muxer;
        readonly Substream substream;
        int windowCredit = 256 * 1024;

        public YamuxSubstream(uint streamId, YamuxMuxer muxer, string name)
        {
            StreamId = streamId;
            this.muxer = muxer;
            substream = new YamuxSubstreamAdapter(this)
            {
                Id = (long)streamId,
                Name = name,
                Muxer = muxer,
            };
        }

        public uint StreamId { get; }

        public void AddData(byte[] data) => substream.AddData(data);

        public void NoMoreData() => substream.NoMoreData();

        public void AddWindowCredit(int delta)
        {
            Interlocked.Add(ref windowCredit, delta);
        }

        public Substream AsSubstream() => substream;

        public Task WriteDataAsync(byte[] data, int offset, int count, CancellationToken cancel)
            => muxer.WriteDataAsync(StreamId, data, offset, count, cancel);

        public Task CloseAsync(CancellationToken cancel)
            => muxer.WriteHeaderAsync(1, 4, StreamId, 0, cancel); // TypeWindowUpdate, FlagFIN
    }

    /// <summary>
    ///   Adapter that makes a YamuxSubstream behave like a mplex Substream.
    /// </summary>
    internal class YamuxSubstreamAdapter : Substream
    {
        internal readonly YamuxSubstream Inner;

        public YamuxSubstreamAdapter(YamuxSubstream inner)
        {
            Inner = inner;
        }

        public override async Task FlushAsync(CancellationToken cancel)
        {
            // Yamux sends data directly per write, no buffering needed
            // But we need the outStream data if any was written via Write()
            // Use reflection to access the parent's outStream... 
            // Actually, let's override Write to send directly.
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            WriteAsync(buffer, offset, count).GetAwaiter().GetResult();
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return Inner.WriteDataAsync(buffer, offset, count, cancellationToken);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Inner.CloseAsync(default).GetAwaiter().GetResult();
            }
            // Don't call base.Dispose which tries to use mplex Muxer
        }
    }
}
