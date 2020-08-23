using FluentAssertions;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace CryptoHelpers.Test
{
    public class AsymmetricEncryptionTest
    {
        [Fact]
        public void GenerateRsaKeyPair()
        {
            var rsa = RSA.Create(2048);

            rsa.KeySize.Should().Be(2048);
        }

        [Fact]
        public void SharePublicKey()
        {
            var rsa = RSA.Create(2048);
            var publicKey = rsa.ExportRSAPublicKey();
            publicKey.Length.Should().Be((2048 + 112) / 8);
        }

        [Fact]
        public void EncryptSymmetricKey()
        {
            var rsa = RSA.Create(2048);
            var publicKey = rsa.ExportRSAPublicKey();

            var key = SymmetricAlgorithm.Create("AES").Key;

            byte[] encryptedKey = AsymmetricHelpers.EncryptWithRsa(publicKey, key);
            byte[] decryptedKey = AsymmetricHelpers.DecryptWithRsa(rsa, encryptedKey);

            decryptedKey.Should().Equal(key);
        }

        [Fact]
        public void SignMessage()
        {
            var rsa = RSA.Create(2048);
            var publicKey = rsa.ExportRSAPublicKey();

            string message = "Alice knows Bob's secret.";
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);

            byte[] signatureBytes = AsymmetricHelpers.SignMessage(rsa, messageBytes);
            bool verified = AsymmetricHelpers.VerifySignature(publicKey, messageBytes, signatureBytes);

            verified.Should().BeTrue();
        }
    }
}
