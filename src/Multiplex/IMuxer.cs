using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace PeerTalk.Multiplex
{
    /// <summary>
    ///   A stream multiplexer interface.
    /// </summary>
    /// <remarks>
    ///   Both mplex and yamux implement this interface, allowing the connection
    ///   handshake to be muxer-agnostic.
    /// </remarks>
    public interface IMuxer
    {
        /// <summary>
        ///   The peer connection that owns this muxer.
        /// </summary>
        PeerConnection Connection { get; set; }

        /// <summary>
        ///   The underlying channel stream.
        /// </summary>
        Stream Channel { get; set; }

        /// <summary>
        ///   Creates a new substream with the specified name.
        /// </summary>
        Task<Substream> CreateStreamAsync(string name = "", CancellationToken cancel = default);

        /// <summary>
        ///   Removes a substream.
        /// </summary>
        Task<Substream> RemoveStreamAsync(Substream stream, CancellationToken cancel = default);

        /// <summary>
        ///   Process incoming muxer frames.
        /// </summary>
        Task ProcessRequestsAsync(CancellationToken cancel = default);

        /// <summary>
        ///   Acquires write access to the underlying channel.
        /// </summary>
        Task<IDisposable> AcquireWriteAccessAsync();

        /// <summary>
        ///   Raised when the remote end creates a new stream.
        /// </summary>
        event EventHandler<Substream> SubstreamCreated;

        /// <summary>
        ///   Raised when a stream is closed.
        /// </summary>
        event EventHandler<Substream> SubstreamClosed;
    }
}
