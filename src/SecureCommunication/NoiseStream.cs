using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace PeerTalk.SecureCommunication
{
    /// <summary>
    ///   A duplex stream encrypted with Noise transport keys (ChaChaPoly).
    /// </summary>
    /// <remarks>
    ///   Messages are framed as [uint16 length | encrypted payload + poly1305 tag].
    ///   Maximum plaintext per frame is 65535 - 16 = 65519 bytes.
    /// </remarks>
    internal class NoiseStream : Stream
    {
        const int TagLen = 16;
        const int LengthPrefixLen = 2;
        const int MaxPlaintext = 65535 - TagLen;

        readonly Stream inner;
        readonly byte[] sendKey;
        readonly byte[] recvKey;
        ulong sendNonce;
        ulong recvNonce;

        // Read buffer
        byte[] readBuffer;
        int readOffset;
        int readCount;

        public NoiseStream(Stream inner, byte[] sendKey, byte[] recvKey)
        {
            this.inner = inner;
            this.sendKey = sendKey;
            this.recvKey = recvKey;
        }

        public override bool CanRead => inner.CanRead;
        public override bool CanWrite => inner.CanWrite;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count)
        {
            return ReadAsync(buffer, offset, count).GetAwaiter().GetResult();
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (readBuffer != null && readOffset < readCount)
            {
                int n = Math.Min(count, readCount - readOffset);
                Array.Copy(readBuffer, readOffset, buffer, offset, n);
                readOffset += n;
                return n;
            }

            // Read next frame: 2-byte big-endian length prefix
            var lenBuf = new byte[LengthPrefixLen];
            if (!await ReadExactlyAsync(inner, lenBuf, 0, LengthPrefixLen, cancellationToken).ConfigureAwait(false))
                return 0; // EOF

            int frameLen = (lenBuf[0] << 8) | lenBuf[1];
            if (frameLen == 0)
                return 0;

            var ciphertext = new byte[frameLen];
            if (!await ReadExactlyAsync(inner, ciphertext, 0, frameLen, cancellationToken).ConfigureAwait(false))
                throw new EndOfStreamException("Truncated noise frame");

            readBuffer = Decrypt(ciphertext);
            readOffset = 0;
            readCount = readBuffer.Length;

            int copied = Math.Min(count, readCount);
            Array.Copy(readBuffer, 0, buffer, offset, copied);
            readOffset = copied;
            return copied;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            WriteAsync(buffer, offset, count).GetAwaiter().GetResult();
        }

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            while (count > 0)
            {
                int chunk = Math.Min(count, MaxPlaintext);
                var plaintext = new byte[chunk];
                Array.Copy(buffer, offset, plaintext, 0, chunk);

                var ciphertext = Encrypt(plaintext);

                var lenBuf = new byte[LengthPrefixLen];
                lenBuf[0] = (byte)(ciphertext.Length >> 8);
                lenBuf[1] = (byte)(ciphertext.Length);

                await inner.WriteAsync(lenBuf, 0, LengthPrefixLen, cancellationToken).ConfigureAwait(false);
                await inner.WriteAsync(ciphertext, 0, ciphertext.Length, cancellationToken).ConfigureAwait(false);

                offset += chunk;
                count -= chunk;
            }
        }

        public override void Flush() => inner.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);

        protected override void Dispose(bool disposing)
        {
            if (disposing) inner.Dispose();
            base.Dispose(disposing);
        }

        byte[] Encrypt(byte[] plaintext)
        {
            var cipher = new ChaCha20Poly1305();
            var nonceBytes = MakeNonce(sendNonce++);
            var parameters = new AeadParameters(new KeyParameter(sendKey), 128, nonceBytes);
            cipher.Init(true, parameters);
            var output = new byte[plaintext.Length + TagLen];
            int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
            cipher.DoFinal(output, len);
            return output;
        }

        byte[] Decrypt(byte[] ciphertext)
        {
            var cipher = new ChaCha20Poly1305();
            var nonceBytes = MakeNonce(recvNonce++);
            var parameters = new AeadParameters(new KeyParameter(recvKey), 128, nonceBytes);
            cipher.Init(false, parameters);
            var output = new byte[ciphertext.Length - TagLen];
            int len = cipher.ProcessBytes(ciphertext, 0, ciphertext.Length, output, 0);
            cipher.DoFinal(output, len);
            return output;
        }

        static byte[] MakeNonce(ulong n)
        {
            // libp2p noise nonce: 4 bytes zero + 8 bytes little-endian counter
            var nonce = new byte[12];
            nonce[4] = (byte)(n);
            nonce[5] = (byte)(n >> 8);
            nonce[6] = (byte)(n >> 16);
            nonce[7] = (byte)(n >> 24);
            nonce[8] = (byte)(n >> 32);
            nonce[9] = (byte)(n >> 40);
            nonce[10] = (byte)(n >> 48);
            nonce[11] = (byte)(n >> 56);
            return nonce;
        }

        static async Task<bool> ReadExactlyAsync(Stream stream, byte[] buffer, int offset, int count, CancellationToken cancel)
        {
            int totalRead = 0;
            while (totalRead < count)
            {
                int n = await stream.ReadAsync(buffer, offset + totalRead, count - totalRead, cancel).ConfigureAwait(false);
                if (n == 0) return totalRead > 0 ? throw new EndOfStreamException() : false;
                totalRead += n;
            }
            return true;
        }
    }
}
