using System.Security.Cryptography;
using System.Text;

namespace CryptoHelpers
{
    public class HashHelpers
    {
        public static byte[] ComputeHash(string message)
        {
            var sha512 = HashAlgorithm.Create("SHA-512");
            var bytes = Encoding.UTF8.GetBytes(message);
            return sha512.ComputeHash(bytes);
        }

        public static byte[] GenerateSalt()
        {
            var bytes = new byte[16];
            var random = RandomNumberGenerator.Create();
            random.GetBytes(bytes);
            return bytes;
        }

        public static byte[] DeriveKey(string passphrase, byte[] salt)
        {
            int iterationCount = 10000;
            int keyLength = 256;
            var pbkdf = new Rfc2898DeriveBytes(passphrase, salt, iterationCount,
                HashAlgorithmName.SHA256);
            var key = pbkdf.GetBytes(keyLength / 8);
            return key;
        }
    }
}
