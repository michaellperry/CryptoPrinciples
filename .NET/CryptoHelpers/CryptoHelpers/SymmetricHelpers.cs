using System.IO;
using System.Security.Cryptography;

namespace CryptoHelpers
{
    public class SymmetricHelpers
    {
        public static byte[] EncryptWithAes(string message, SymmetricAlgorithm aes)
        {
            MemoryStream memoryStream = new MemoryStream();
            var cryptoStream = new CryptoStream(
                memoryStream,
                aes.CreateEncryptor(),
                CryptoStreamMode.Write);

            using (var writer = new StreamWriter(cryptoStream))
            {
                writer.Write(message);
            }

            return memoryStream.ToArray();
        }

        public static string DecryptWithAes(byte[] ciphertext, byte[] key, byte[] iv)
        {
            var aes = SymmetricAlgorithm.Create("AES");
            aes.Key = key;
            aes.IV = iv;

            MemoryStream memoryStream = new MemoryStream(ciphertext);
            var cryptoStream = new CryptoStream(
                memoryStream,
                aes.CreateDecryptor(),
                CryptoStreamMode.Read);

            using (var reader = new StreamReader(cryptoStream))
            {
                return reader.ReadToEnd();
            }
        }
    }
}