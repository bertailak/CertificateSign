using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace CertificateSign
{
    class Program
    {
        const string certPath = @"C:\RSA256.p12";
        const string certPassword = "password";

        static void Main(string[] args)
        {
            X509Certificate2 cert = new X509Certificate2(certPath, certPassword, X509KeyStorageFlags.Exportable);
            UnicodeEncoding encoding = new UnicodeEncoding();
            byte[] data = encoding.GetBytes("test");

            byte[] signature = GetSignature(data, cert);
            bool ver = ValidateSignature(data, signature, cert);

            string signedString = Convert.ToBase64String(signature);
            byte[] signedByte = Convert.FromBase64String(signedString);

            string publicKey = cert.PublicKey.Key.ToXmlString(false);
            bool res = ValidateSignatureByPublicKey(data, signature, publicKey);
        }

        public static byte[] GetSignature(byte[] inputData, X509Certificate2 cert)
        {
            using (var rsa = cert.GetRSAPrivateKey())
            {
                return rsa.SignData(inputData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        public static bool ValidateSignature(byte[] inputData, byte[] signature, X509Certificate2 cert)
        {
            using (var rsa = cert.GetRSAPublicKey())
            {
                return rsa.VerifyData(inputData, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        static void GetCertificates()
        {
            X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
            X509Certificate2Collection fcollection = (X509Certificate2Collection)collection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
            X509Certificate2Collection scollection = X509Certificate2UI.SelectFromCollection(fcollection, "Test Certificate Select", "Select a certificate from the following list to get information on that certificate", X509SelectionFlag.MultiSelection);
            Console.WriteLine("Number of certificates: {0}{1}", scollection.Count, Environment.NewLine);

            foreach (X509Certificate2 x509 in scollection)
            {
                try
                {
                    byte[] rawdata = x509.RawData;
                    Console.WriteLine("Content Type: {0}{1}", X509Certificate2.GetCertContentType(rawdata), Environment.NewLine);
                    Console.WriteLine("Friendly Name: {0}{1}", x509.FriendlyName, Environment.NewLine);
                    Console.WriteLine("Certificate Verified?: {0}{1}", x509.Verify(), Environment.NewLine);
                    Console.WriteLine("Simple Name: {0}{1}", x509.GetNameInfo(X509NameType.SimpleName, true), Environment.NewLine);
                    Console.WriteLine("Signature Algorithm: {0}{1}", x509.SignatureAlgorithm.FriendlyName, Environment.NewLine);
                    Console.WriteLine("Public Key: {0}{1}", x509.PublicKey.Key.ToXmlString(false), Environment.NewLine);
                    Console.WriteLine("Certificate Archived?: {0}{1}", x509.Archived, Environment.NewLine);
                    Console.WriteLine("Length of Raw Data: {0}{1}", x509.RawData.Length, Environment.NewLine);
                    //X509Certificate2UI.DisplayCertificate(x509);
                    x509.Reset();
                }
                catch (CryptographicException)
                {
                    Console.WriteLine("Information could not be written out for this certificate.");
                }
            }
            store.Close();
        }

        public static bool ValidateSignatureByPublicKey(byte[] inputData, byte[] signature, string publicKey)
        {
            XmlDocument xdoc = new XmlDocument();
            xdoc.LoadXml(publicKey);

            RSAParameters RSAKeyInfo = new RSAParameters();
            RSAKeyInfo.Modulus = Convert.FromBase64String(xdoc.SelectSingleNode("./RSAKeyValue/Modulus").InnerText);
            RSAKeyInfo.Exponent = Convert.FromBase64String(xdoc.SelectSingleNode("./RSAKeyValue/Exponent").InnerText);

            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            RSA.ImportParameters(RSAKeyInfo);
            return RSA.VerifyData(inputData, CryptoConfig.MapNameToOID("SHA256"), signature);
        }
    }
}
