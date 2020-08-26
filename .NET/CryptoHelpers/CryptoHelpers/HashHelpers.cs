using System.Security.Cryptography;
using System.Text;

namespace CryptoHelpers
{
    public class HashHelpers
    {
        public static byte[] ComputeHash(string message)
        {
            return null;
        }

        public static byte[] GenerateSalt()
        {
            var bytes = new byte[16];
            return bytes;
        }

        public static byte[] DeriveKey(string passphrase, byte[] salt)
        {
            int iterationCount = 10000;
            int keyLength = 256;
            return null;
        }
    }
}
