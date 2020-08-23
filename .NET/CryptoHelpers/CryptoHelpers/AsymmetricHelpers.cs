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
        public static byte[] EncryptWithRsa(string publicKey, byte[] plaintext)
        {
            return null;
        }

        public static byte[] DecryptWithRsa(RSA rsa, byte[] ciphertext)
        {
            return null;
        }

        public static byte[] SignMessage(RSA rsa, byte[] messageBytes)
        {
            return rsa.SignData(messageBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        }

        public static bool VerifySignature(string publicKey, byte[] messageBytes, byte[] signatureBytes)
        {
            var parameters = CreateParameters(publicKey);
            var rsa = RSA.Create(parameters);
            return false;
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
    }
}