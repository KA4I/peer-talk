using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using BcChaCha20Poly1305 = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;

namespace PeerTalk.SecureCommunication
{
    /// <summary>
    ///   Implements the Noise XX handshake pattern for libp2p.
    /// </summary>
    /// <remarks>
    ///   See https://github.com/libp2p/specs/blob/master/noise/README.md
    ///   Uses XX pattern: XX(s, rs) with Curve25519, ChaChaPoly, SHA256.
    /// </remarks>
    internal class NoiseHandshake
    {
        static readonly byte[] ProtocolName = Encoding.ASCII.GetBytes("Noise_XX_25519_ChaChaPoly_SHA256");
        const int KeyLen = 32;
        const int TagLen = 16;

        // Handshake state
        byte[] s_priv;      // local static private key (25519)
        byte[] s_pub;       // local static public key (25519)
        byte[] e_priv;      // local ephemeral private key
        byte[] e_pub;       // local ephemeral public key
        byte[] rs;          // remote static public key
        byte[] re;          // remote ephemeral public key

        // Symmetric state
        byte[] ck;          // chaining key
        byte[] h;           // handshake hash
        byte[] k;           // current cipher key (null until first DH)
        ulong n;            // nonce counter

        bool initiator;

        // Result after Split()
        internal byte[] SendKey;
        internal byte[] RecvKey;

        public NoiseHandshake(byte[] staticPrivateKey, byte[] staticPublicKey, bool initiator)
        {
            s_priv = staticPrivateKey;
            s_pub = staticPublicKey;
            this.initiator = initiator;

            // Initialize symmetric state with protocol name
            if (ProtocolName.Length == 32)
            {
                h = (byte[])ProtocolName.Clone();
            }
            else
            {
                h = Sha256(ProtocolName);
            }
            ck = (byte[])h.Clone();
            k = null;
            n = 0;
        }

        /// <summary>
        ///   Mix the prologue into the handshake hash.
        /// </summary>
        public void MixPrologue(byte[] prologue)
        {
            MixHash(prologue);
        }

        /// <summary>
        ///   Initiator creates message 1: -> e
        /// </summary>
        public byte[] WriteMessage1(byte[] payload)
        {
            GenerateEphemeral();
            var msg = new MemoryStream();

            // e
            msg.Write(e_pub, 0, KeyLen);
            MixHash(e_pub);

            // payload (plaintext, mixed into hash)
            var encrypted = EncryptAndHash(payload);
            msg.Write(encrypted, 0, encrypted.Length);

            return msg.ToArray();
        }

        /// <summary>
        ///   Responder reads message 1: -> e
        /// </summary>
        public byte[] ReadMessage1(byte[] message)
        {
            int offset = 0;

            // re
            re = new byte[KeyLen];
            Array.Copy(message, offset, re, 0, KeyLen);
            offset += KeyLen;
            MixHash(re);

            // payload
            var remaining = new byte[message.Length - offset];
            Array.Copy(message, offset, remaining, 0, remaining.Length);
            return DecryptAndHash(remaining);
        }

        /// <summary>
        ///   Responder creates message 2: -> e, ee, s, es
        /// </summary>
        public byte[] WriteMessage2(byte[] payload)
        {
            GenerateEphemeral();
            var msg = new MemoryStream();

            // e
            msg.Write(e_pub, 0, KeyLen);
            MixHash(e_pub);

            // ee
            MixKey(DH(e_priv, re));

            // s (encrypted)
            var encS = EncryptAndHash(s_pub);
            msg.Write(encS, 0, encS.Length);

            // es
            MixKey(DH(s_priv, re));

            // payload (encrypted)
            var encPayload = EncryptAndHash(payload);
            msg.Write(encPayload, 0, encPayload.Length);

            return msg.ToArray();
        }

        /// <summary>
        ///   Initiator reads message 2: -> e, ee, s, es
        /// </summary>
        public byte[] ReadMessage2(byte[] message)
        {
            int offset = 0;

            // re
            re = new byte[KeyLen];
            Array.Copy(message, offset, re, 0, KeyLen);
            offset += KeyLen;
            MixHash(re);

            // ee
            MixKey(DH(e_priv, re));

            // s (encrypted = 32 + 16 tag)
            var encS = new byte[KeyLen + TagLen];
            Array.Copy(message, offset, encS, 0, encS.Length);
            offset += encS.Length;
            rs = DecryptAndHash(encS);

            // es
            MixKey(DH(e_priv, rs));

            // payload
            var remaining = new byte[message.Length - offset];
            Array.Copy(message, offset, remaining, 0, remaining.Length);
            return DecryptAndHash(remaining);
        }

        /// <summary>
        ///   Initiator creates message 3: -> s, se
        /// </summary>
        public byte[] WriteMessage3(byte[] payload)
        {
            var msg = new MemoryStream();

            // s (encrypted)
            var encS = EncryptAndHash(s_pub);
            msg.Write(encS, 0, encS.Length);

            // se
            MixKey(DH(s_priv, re));

            // payload (encrypted)
            var encPayload = EncryptAndHash(payload);
            msg.Write(encPayload, 0, encPayload.Length);

            return msg.ToArray();
        }

        /// <summary>
        ///   Responder reads message 3: -> s, se
        /// </summary>
        public byte[] ReadMessage3(byte[] message)
        {
            int offset = 0;

            // s (encrypted = 32 + 16 tag)
            var encS = new byte[KeyLen + TagLen];
            Array.Copy(message, offset, encS, 0, encS.Length);
            offset += encS.Length;
            rs = DecryptAndHash(encS);

            // se: responder uses own ephemeral private key + remote static public key
            MixKey(DH(e_priv, rs));

            // payload
            var remaining = new byte[message.Length - offset];
            Array.Copy(message, offset, remaining, 0, remaining.Length);
            return DecryptAndHash(remaining);
        }

        /// <summary>
        ///   Derive the transport keys after the handshake completes.
        /// </summary>
        public void Split()
        {
            var (k1, k2) = HkdfSplit(ck);
            if (initiator)
            {
                SendKey = k1;
                RecvKey = k2;
            }
            else
            {
                SendKey = k2;
                RecvKey = k1;
            }
        }

        /// <summary>
        ///   Get the remote static public key (available after message 2 for initiator, message 3 for responder).
        /// </summary>
        public byte[] RemoteStaticKey => rs;

        // --- Primitives ---

        void GenerateEphemeral()
        {
            var gen = new X25519KeyPairGenerator();
            gen.Init(new X25519KeyGenerationParameters(new SecureRandom()));
            var pair = gen.GenerateKeyPair();
            e_priv = ((X25519PrivateKeyParameters)pair.Private).GetEncoded();
            e_pub = ((X25519PublicKeyParameters)pair.Public).GetEncoded();
        }

        static byte[] DH(byte[] privKey, byte[] pubKey)
        {
            var priv = new X25519PrivateKeyParameters(privKey);
            var pub = new X25519PublicKeyParameters(pubKey);
            var agreement = new X25519Agreement();
            agreement.Init(priv);
            var shared = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(pub, shared, 0);
            return shared;
        }

        void MixHash(byte[] data)
        {
            h = Sha256(Concat(h, data));
        }

        void MixKey(byte[] inputKeyMaterial)
        {
            var (output1, output2) = HkdfSplit(ck, inputKeyMaterial);
            ck = output1;
            k = output2;
            n = 0;
        }

        byte[] EncryptAndHash(byte[] plaintext)
        {
            byte[] ciphertext;
            if (k == null)
            {
                ciphertext = plaintext;
            }
            else
            {
                ciphertext = ChaChaEncrypt(k, n, h, plaintext);
                n++;
            }
            MixHash(ciphertext);
            return ciphertext;
        }

        byte[] DecryptAndHash(byte[] ciphertext)
        {
            byte[] plaintext;
            if (k == null)
            {
                plaintext = ciphertext;
            }
            else
            {
                plaintext = ChaChaDecrypt(k, n, h, ciphertext);
                n++;
            }
            MixHash(ciphertext);
            return plaintext;
        }

        // --- Crypto helpers ---

        static byte[] Sha256(byte[] data)
        {
            var digest = new Org.BouncyCastle.Crypto.Digests.Sha256Digest();
            digest.BlockUpdate(data, 0, data.Length);
            var hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);
            return hash;
        }

        static byte[] Concat(byte[] a, byte[] b)
        {
            var result = new byte[a.Length + b.Length];
            Array.Copy(a, 0, result, 0, a.Length);
            Array.Copy(b, 0, result, a.Length, b.Length);
            return result;
        }

        static (byte[], byte[]) HkdfSplit(byte[] chainingKey, byte[] inputKeyMaterial = null)
        {
            // HKDF using HMAC-SHA256
            var ikm = inputKeyMaterial ?? Array.Empty<byte>();

            // Extract
            var prk = HmacSha256(chainingKey, ikm);

            // Expand (two outputs)
            var t1 = HmacSha256(prk, new byte[] { 1 });
            var t2 = HmacSha256(prk, Concat(t1, new byte[] { 2 }));
            return (t1, t2);
        }

        static byte[] HmacSha256(byte[] key, byte[] data)
        {
            var hmac = new Org.BouncyCastle.Crypto.Macs.HMac(new Org.BouncyCastle.Crypto.Digests.Sha256Digest());
            hmac.Init(new KeyParameter(key));
            hmac.BlockUpdate(data, 0, data.Length);
            var result = new byte[hmac.GetMacSize()];
            hmac.DoFinal(result, 0);
            return result;
        }

        static byte[] ChaChaEncrypt(byte[] key, ulong nonce, byte[] ad, byte[] plaintext)
        {
            var cipher = new BcChaCha20Poly1305();
            var nonceBytes = new byte[12];
            // little-endian nonce per Noise spec
            nonceBytes[4] = (byte)(nonce);
            nonceBytes[5] = (byte)(nonce >> 8);
            nonceBytes[6] = (byte)(nonce >> 16);
            nonceBytes[7] = (byte)(nonce >> 24);
            nonceBytes[8] = (byte)(nonce >> 32);
            nonceBytes[9] = (byte)(nonce >> 40);
            nonceBytes[10] = (byte)(nonce >> 48);
            nonceBytes[11] = (byte)(nonce >> 56);

            var parameters = new AeadParameters(new KeyParameter(key), 128, nonceBytes, ad);
            cipher.Init(true, parameters);

            var output = new byte[plaintext.Length + TagLen];
            int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
            cipher.DoFinal(output, len);
            return output;
        }

        static byte[] ChaChaDecrypt(byte[] key, ulong nonce, byte[] ad, byte[] ciphertext)
        {
            var cipher = new BcChaCha20Poly1305();
            var nonceBytes = new byte[12];
            nonceBytes[4] = (byte)(nonce);
            nonceBytes[5] = (byte)(nonce >> 8);
            nonceBytes[6] = (byte)(nonce >> 16);
            nonceBytes[7] = (byte)(nonce >> 24);
            nonceBytes[8] = (byte)(nonce >> 32);
            nonceBytes[9] = (byte)(nonce >> 40);
            nonceBytes[10] = (byte)(nonce >> 48);
            nonceBytes[11] = (byte)(nonce >> 56);

            var parameters = new AeadParameters(new KeyParameter(key), 128, nonceBytes, ad);
            cipher.Init(false, parameters);

            var output = new byte[ciphertext.Length - TagLen];
            int len = cipher.ProcessBytes(ciphertext, 0, ciphertext.Length, output, 0);
            cipher.DoFinal(output, len);
            return output;
        }
    }
}
