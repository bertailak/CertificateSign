using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace CertificateSign
{
    class Program
    {
        const string certPath = @"C:\repo\own\ecp\Sherkhan-2021 123456\RSA256_983cadcfdd55a14bf33799d1aa1665f081d2622f.p12";
        const string certPassword = "Goha1998";

        static void Main(string[] args)
        {
            X509Certificate2 cert = new X509Certificate2(certPath, certPassword, X509KeyStorageFlags.Exportable);
            UnicodeEncoding encoding = new UnicodeEncoding();
            byte[] data = encoding.GetBytes("<Root/>");

            byte[] signature = GetSignature(data, cert);
            bool ver = ValidateSignature(data, signature, cert);

            string signedString = Convert.ToBase64String(signature);
            byte[] signedByte = Convert.FromBase64String(signedString);

            string publicKey = cert.PublicKey.Key.ToXmlString(false);
            var publicKey2 = cert.PublicKey.Key.ToString();
            bool res = ValidateSignatureByPublicKey(data, signature, publicKey);

            SignXMLDocument(data, cert, "sign.xml");
            bool verxml = VerifyXMLDocument("sign.xml", cert);

        }

        private static void SignXMLDocument(byte[] xmlDocumentBuffer, X509Certificate2 certificate, string signedXMLPath)
        {
            // Load xmlDocument data in to an XML Document
            XmlDocument xmlDocument = new XmlDocument();
            string xml = $"<Root><Broker description =\"Наименование брокера\">АО \"Jýsan Invest\"</Broker>"
   + "<ReportDate description=\"Дата выдачи\">24.05.2021</ReportDate>"
   + "<Client description=\"Клиент\">ӘБІЛДА МИРАС НҰРЖАНҰЛЫ</Client>"
   + "<AccountNum description=\"Номер лицевого счета\">01010108848</AccountNum>"
   + "<Email description=\"Электронный адрес клиента\">miras703@gmail.com</Email>"
   + "<ReportType description=\"ReportType\">Уведомление об открытии лицевого счета</ReportType>"
   + "<OperationType description=\"Вид операции\">Открытие лицевого счета</OperationType>"
   + "<ContractNum description=\"Договор\">№8858 24.05.2021</ContractNum>"
   + "<OrderNum description=\"Данные приказа\">№1 от 24.05.2021</OrderNum>"
   + "<OrderExecDate description=\"Дата исполнения приказа\">24.05.2021</OrderExecDate>"
   + "<InternetLogin description=\"Логин\">3130544</InternetLogin>"
   + "<clientID description=\"Идентификатор клиента\">3130544</clientID></Root>";
            xmlDocument.LoadXml(xml);

            // Sign the XML document using the certificate private key
            using (var rsaKey = certificate.PrivateKey)
            {
                var signedXml = new SignedXml(xmlDocument);
                signedXml.SigningKey = rsaKey;

                var reference = new Reference();
                reference.Uri = "";

                var env = new XmlDsigEnvelopedSignatureTransform();
                reference.AddTransform(env);

                signedXml.AddReference(reference);

                signedXml.ComputeSignature();

                var xmlDigitalSignature = signedXml.GetXml();

                xmlDocument.DocumentElement.AppendChild(xmlDocument.ImportNode(xmlDigitalSignature, true));

                xmlDocument.Save(signedXMLPath);
            }
        }
        private static bool VerifyXMLDocument(string xmlFilePath, X509Certificate2 certificate)
        {
            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.Load(xmlFilePath);

            var signedXml = new SignedXml(xmlDocument);

            // Load the XML Signature
            var nodeList = xmlDocument.GetElementsByTagName("Signature");

            signedXml.LoadXml((XmlElement)nodeList[0]);


            //XmlDocument xdoc = new XmlDocument();
            //xdoc.LoadXml(certificate.PublicKey.Key.ToXmlString(false));

            //RSAParameters RSAKeyInfo = new RSAParameters();
            //RSAKeyInfo.Modulus = Convert.FromBase64String(xdoc.SelectSingleNode("./RSAKeyValue/Modulus").InnerText);
            //RSAKeyInfo.Exponent = Convert.FromBase64String(xdoc.SelectSingleNode("./RSAKeyValue/Exponent").InnerText);

            //RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            //RSA.ImportParameters(RSAKeyInfo);
            //bool result = signedXml.CheckSignature(RSA);

            //return RSA.VerifyData(inputData, CryptoConfig.MapNameToOID("SHA256"), signature);
            // Verify the integrity of the xml document

            using (var rsaKey = certificate.PublicKey.Key)
            {
                return signedXml.CheckSignature(rsaKey);
            }
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
