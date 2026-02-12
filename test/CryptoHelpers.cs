using System;
using System.IO;
using Ipfs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using ProtoBuf;

namespace PeerTalk
{
    public static class CryptoHelpers
    {
        public static AsymmetricCipherKeyPair GetKey()
        {
            var keyAGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
            keyAGen.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), new SecureRandom(), 2048, 25));
            var asymmetricCipherKeyPair = keyAGen.GenerateKeyPair();
            return asymmetricCipherKeyPair;
        }

        public static string CreatePublicKey(this AsymmetricCipherKeyPair key)
        {
            var spki = SubjectPublicKeyInfoFactory
                .CreateSubjectPublicKeyInfo(key.Public)
                .GetDerEncoded();
            // Add protobuf cruft.
            var publicKey = new PublicKeyMessage
            {
                Data = spki
            };
            if (key.Public is RsaKeyParameters)
                publicKey.Type = KeyType.RSA;
            else if (key.Public is Ed25519PublicKeyParameters)
                publicKey.Type = KeyType.Ed25519;
            else if (key.Public is ECPublicKeyParameters)
                publicKey.Type = KeyType.Secp256k1;
            else
                throw new NotSupportedException($"The key type {key.Public.GetType().Name} is not supported.");

            using (var ms = new MemoryStream())
            {
                Serializer.Serialize(ms, publicKey);
                return Convert.ToBase64String(ms.ToArray());
            }
        }


        public static MultiHash CreateKeyId(this AsymmetricKeyParameter key)
        {
            var spki = SubjectPublicKeyInfoFactory
                .CreateSubjectPublicKeyInfo(key)
                .GetDerEncoded();

            // Add protobuf cruft.
            var publicKey = new PublicKeyMessage
            {
                Data = spki
            };
            if (key is RsaKeyParameters)
                publicKey.Type = KeyType.RSA;
            else if (key is ECPublicKeyParameters)
                publicKey.Type = KeyType.Secp256k1;
            else if (key is Ed25519PublicKeyParameters)
                publicKey.Type = KeyType.Ed25519;
            else
                throw new NotSupportedException($"The key type {key.GetType().Name} is not supported.");

            using (var ms = new MemoryStream())
            {
                Serializer.Serialize(ms, publicKey);

                // If the length of the serialized bytes <= 42, then we compute the "identity" multihash of 
                // the serialized bytes. The idea here is that if the serialized byte array 
                // is short enough, we can fit it in a multihash verbatim without having to 
                // condense it using a hash function.
                var alg = (ms.Length <= 48) ? "identity" : "sha2-256";

                ms.Position = 0;
                return MultiHash.ComputeHash(ms, alg);
            }
        }

        enum KeyType
        {
            RSA = 0,
            Ed25519 = 1,
            Secp256k1 = 2,
            ECDH = 4
        }

        [ProtoContract]
        class PublicKeyMessage
        {
            [ProtoMember(1, IsRequired = true)] 
            public KeyType Type { get; set; }

            [ProtoMember(2, IsRequired = true)] 
            public byte[] Data { get; set; }
        }
    }
}