using System;
using Xunit;
using FluentAssertions;

namespace CryptoHelpers.Test
{
    public class HashTest
    {
        [Fact]
        public void HashAMessage()
        {
            string message = "Alice knows Bob's secret.";

            byte[] digest = HashHelpers.ComputeHash(message);

            digest.Length.Should().Be(64);
        }

        [Fact]
        public void PasswordBasedKeyDerivationFunction()
        {
            string passphrase = "Twas brillig and the slithy toves did gyre and gimble in the wabe";
            byte[] salt = HashHelpers.GenerateSalt();

            byte[] key = HashHelpers.DeriveKey(passphrase, salt);

            key.Length.Should().Be(32);
        }
    }
}
