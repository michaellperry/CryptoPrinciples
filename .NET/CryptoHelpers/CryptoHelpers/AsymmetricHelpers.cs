using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System;
using System.IO;
using System.Security.Cryptography;

namespace CryptoHelpers
{
    public class AsymmetricHelpers
    {
        public static byte[] EncryptWithRsa(byte[] publicKey, byte[] plaintext)
        {
            var parameters = CreateParameters(publicKey);
            var rsa = RSA.Create(parameters);
            var ciphertext = rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA512);

            return ciphertext;
        }

        public static byte[] DecryptWithRsa(RSA rsa, byte[] ciphertext)
        {
            var plaintext = rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA512);
            return plaintext;
        }

        public static byte[] SignMessage(RSA rsa, byte[] messageBytes)
        {
            return rsa.SignData(messageBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        }

        public static bool VerifySignature(byte[] publicKey, byte[] messageBytes, byte[] signatureBytes)
        {
            var parameters = CreateParameters(publicKey);
            var rsa = RSA.Create(parameters);
            return rsa.VerifyData(messageBytes, signatureBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        }

        private static RSAParameters CreateParameters(byte[] publicKey)
        {
            var pem = "-----BEGIN RSA PUBLIC KEY-----\n" + Convert.ToBase64String(publicKey) + "\n-----END RSA PUBLIC KEY-----";
            var textReader = new StringReader(pem);
            PemReader reader = new PemReader(textReader);
            var parameters = (RsaKeyParameters)reader.ReadObject();

            return new RSAParameters
            {
                Exponent = parameters.Exponent.ToByteArray(),
                Modulus = parameters.Modulus.ToByteArray()
            };
        }
    }
}