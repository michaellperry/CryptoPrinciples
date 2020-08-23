using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptoHelpers
{
    public class AsymmetricHelpers
    {
        public static string WritePEM(string kind, byte[] bytes)
        {
            var builder = new StringBuilder();
            builder.AppendLine($"-----BEGIN {kind}-----");
            string base64 = Convert.ToBase64String(bytes);
            for (int offset = 0; offset < base64.Length; offset += 64)
            {
                builder.AppendLine(base64.Substring(offset, Math.Min(base64.Length - offset, 64)));
            }
            builder.AppendLine($"-----END {kind}-----");
            return builder.ToString();
        }

        public static byte[] EncryptWithRsa(string publicKey, byte[] plaintext)
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

        public static bool VerifySignature(string publicKey, byte[] messageBytes, byte[] signatureBytes)
        {
            var parameters = CreateParameters(publicKey);
            var rsa = RSA.Create(parameters);
            return rsa.VerifyData(messageBytes, signatureBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        }

        private static RSAParameters CreateParameters(string publicKey)
        {
            var textReader = new StringReader(publicKey);
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