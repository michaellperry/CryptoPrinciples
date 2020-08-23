using System;
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
            var modulus = new byte[2048 / 8];
            Array.Copy(publicKey, 9, modulus, 0, 2048 / 8);
            var exponent = new byte[3];
            Array.Copy(publicKey, 11 + 2048 / 8, exponent, 0, 3);

            return new RSAParameters
            {
                Exponent = exponent,
                Modulus = modulus
            };
        }
    }
}