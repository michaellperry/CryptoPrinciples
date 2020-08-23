using FluentAssertions;
using System.Security.Cryptography;
using Xunit;

namespace CryptoHelpers.Test
{
    public class SymmetricEncryptionTest
    {
        [Fact]
        public void GenerateRandomAESKey()
        {
            var aes = SymmetricAlgorithm.Create("AES");

            aes.Key.Length.Should().Be(32);
            aes.IV.Length.Should().Be(16);
        }

        [Fact]
        public void EncryptMessageWithAES()
        {
            string inputMessage = "Alice knows Bob's secret.";

            var aes = SymmetricAlgorithm.Create("AES");

            byte[] ciphertext = SymmetricHelpers.EncryptWithAes(inputMessage, aes);

            var key = aes.Key;
            var iv = aes.IV;

            string outputMessage = SymmetricHelpers.DecryptWithAes(ciphertext, key, iv);

            outputMessage.Should().Be(inputMessage);
        }
    }
}
