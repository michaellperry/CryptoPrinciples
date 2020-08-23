using System.IO;
using System.Security.Cryptography;

namespace CryptoHelpers
{
    public class SymmetricHelpers
    {
        public static byte[] EncryptWithAes(string message, SymmetricAlgorithm aes)
        {
            MemoryStream memoryStream = new MemoryStream();

            using (var writer = new StreamWriter(memoryStream))
            {
                writer.Write(message);
            }

            return null;
        }

        public static string DecryptWithAes(byte[] ciphertext, byte[] key, byte[] iv)
        {
            MemoryStream memoryStream = new MemoryStream(ciphertext);

            using (var reader = new StreamReader(memoryStream))
            {
                return reader.ReadToEnd();
            }
        }
    }
}