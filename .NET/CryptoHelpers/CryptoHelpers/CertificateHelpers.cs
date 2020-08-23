using Org.BouncyCastle.X509;
using System;

namespace CryptoHelpers
{
    public class CertificateHelpers
    {
        public static X509Certificate LoadCertificate(string pem)
        {
            string base64 = pem
                .Replace("-----BEGIN CERTIFICATE-----", "")
                .Replace("-----END CERTIFICATE-----", "");
            var bytes = Convert.FromBase64String(base64);
            var parser = new X509CertificateParser();
            var certificate = parser.ReadCertificate(bytes);
            return certificate;
        }
    }
}