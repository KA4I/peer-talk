using Common.Logging;
using PeerTalk.Multiplex;
using Semver;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace PeerTalk.Protocols
{
    /// <summary>
    ///   The Yamux stream multiplexer protocol.
    /// </summary>
    /// <remarks>
    ///   See https://github.com/hashicorp/yamux/blob/master/spec.md
    ///   Protocol ID: /yamux/1.0.0
    /// </remarks>
    public class Yamux1 : IPeerProtocol
    {
        static readonly ILog log = LogManager.GetLogger(typeof(Yamux1));

        /// <inheritdoc />
        public string Name { get; } = "yamux";

        /// <inheritdoc />
        public SemVersion Version { get; } = new SemVersion(1, 0, 0);

        /// <inheritdoc />
        public override string ToString() => $"/{Name}/{Version}";

        /// <inheritdoc />
        public async Task ProcessMessageAsync(PeerConnection connection, Stream stream, CancellationToken cancel = default)
        {
            log.Debug("Yamux: start processing requests from " + connection.RemoteAddress);

            var muxer = new YamuxMuxer(initiator: false)
            {
                Channel = stream,
                Connection = connection,
            };
            muxer.SubstreamCreated += (s, e) => _ = connection.ReadMessagesAsync(e, CancellationToken.None);

            connection.MuxerEstablished.TrySetResult(muxer);
            await muxer.ProcessRequestsAsync(cancel).ConfigureAwait(false);

            log.Debug("Yamux: stop processing from " + connection.RemoteAddress);
        }
    }
}
