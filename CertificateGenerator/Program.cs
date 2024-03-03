using CommandLine;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;
using System.Configuration;
using System.Reflection;
using System.Text;
using System.Threading.Atomic;

namespace CertificateGenerator
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            ParserResult<CmdMain> result = await Parser.Default.ParseArguments<CmdMain>(args)
                .WithParsedAsync(async cmdMain =>
                {
                    switch (cmdMain.Mode)
                    {
                        case GenerateMode.CA:
                            Console.WriteLine("CA Certificate Generate.");
                            await GenerateCACertificate(cmdMain);
                            break;
                        case GenerateMode.CLIENT:
                            await GenerateClientCertificate(cmdMain);
                            break;
                        case GenerateMode.SERVER:
                            await GenerateServerCertificate(cmdMain);
                            break;
                        default:
                            throw new InvalidOperationException($"unknown mode '{cmdMain.Mode}'");
                    }
                });
            await result.WithNotParsedAsync(async errors =>
            {
                if (errors.IsVersion())
                    PrintVersion(errors.Output());
                await Task.CompletedTask;
            });
        }        

        static async Task GenerateCACertificate(CmdMain cmdMain)
        {
            YamlDotNet.Serialization.Deserializer deserializer = new YamlDotNet.Serialization.Deserializer();
            string str = File.ReadAllText(cmdMain.ConfigFilePath);
            CaCertificateConfiguration configuration = deserializer.Deserialize<CaCertificateConfiguration>(str);
            ConfigurationValidator.Validate(configuration);
            ArgumentNullException.ThrowIfNull(configuration.KeySize);
            ArgumentNullException.ThrowIfNull(configuration.Days);

            SecureRandom secureRandom = new SecureRandom();

            GenerateKey(configuration.KeySize.Value, configuration.KeyFile, secureRandom, out AsymmetricCipherKeyPair keyPair, out PrivateKeyInfo privateKeyInfo, out SubjectPublicKeyInfo subjectPublicKeyInfo);
            X509Name dn = GenerateDN(configuration);

            X509Certificate certificate = GenerateCertificate(dn, configuration.Days.Value, keyPair.Public, subjectPublicKeyInfo, keyPair.Private, configuration.CertificateFile, GenerateMode.CA);

            ArgumentNullException.ThrowIfNull(configuration.Alias);
            GenerateCertificateStore(configuration.Alias, keyPair.Private, configuration.StoreFile, configuration.StorePassword, secureRandom, certificate);

            await Task.CompletedTask;
        }

        private static void GenerateKey(int keySize, string keyFile,  SecureRandom secureRandom, out AsymmetricCipherKeyPair keyPair, out PrivateKeyInfo privateKeyInfo, out SubjectPublicKeyInfo subjectPublicKeyInfo)
        {
            IAsymmetricCipherKeyPairGenerator generator = new RsaKeyPairGenerator();
            KeyGenerationParameters parameters = new KeyGenerationParameters(secureRandom, keySize);
            generator.Init(parameters);
            Console.WriteLine($"key pair generate... : {keySize}");
            keyPair = generator.GenerateKeyPair();
            privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            PemObject pemObject = new PemObject("PRIVATE KEY", privateKeyInfo.GetEncoded());
            FileInfo privateKeyFileInfo = new FileInfo(keyFile);
            if (privateKeyFileInfo.Directory is not null && !privateKeyFileInfo.Directory.Exists)
                privateKeyFileInfo.Directory.Create();
            using (FileStream stream = new FileStream(privateKeyFileInfo.FullName, FileMode.Create, FileAccess.Write))
            {
                using StreamWriter writer = new StreamWriter(stream);
                using PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(pemObject);
            }
            Console.WriteLine($"Private Key File Write : {privateKeyFileInfo.FullName}");
        }

        private static X509Name GenerateDN(Configuration configuration)
        {
            StringBuilder dnBuilder = new StringBuilder($"CN={configuration.CommonName}");
            if (configuration.OrganizationName is not null)
                dnBuilder.Append($", O={configuration.OrganizationName}");
            if (configuration.OrganizationalUnitName is not null)
                dnBuilder.Append($", OU={configuration.OrganizationalUnitName}");
            if (configuration.LocalityName is not null)
                dnBuilder.Append($", L={configuration.LocalityName}");
            if (configuration.StateOrProvinceName is not null)
                dnBuilder.Append($", ST={configuration.StateOrProvinceName}");
            if (configuration.CountryName is not null)
                dnBuilder.Append($", C={configuration.CountryName}");
            if (configuration.Email is not null)
                dnBuilder.Append($", E={configuration.Email}");
            return new X509Name(dnBuilder.ToString());
        }

        private static X509Certificate GenerateCertificate(X509Name dn, int days, AsymmetricKeyParameter publicKey, SubjectPublicKeyInfo subjectPublicKeyInfo, AsymmetricKeyParameter privateKey, string certificateFile, GenerateMode mode, List<string>? alternativeNames = null, List<string>? alternativeAddresses = null, AsymmetricKeyParameter? caPrivateKey = null, X509Certificate? caCertificate = null)
        {
            X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
            Org.BouncyCastle.Math.BigInteger serial = new Org.BouncyCastle.Math.BigInteger(serialNumber.Value.ToString());
            certificateGenerator.SetSerialNumber(serial);
            certificateGenerator.SetIssuerDN(caCertificate is null ? dn : caCertificate.IssuerDN);
            certificateGenerator.SetSubjectDN(dn);

            DateTime notBefore = DateTime.Now;
            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notBefore.AddDays(days));
            certificateGenerator.SetPublicKey(publicKey);
            certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifier(subjectPublicKeyInfo));
            certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifier(caCertificate is null ? subjectPublicKeyInfo : caCertificate.SubjectPublicKeyInfo, 
                new GeneralNames(new GeneralName(caCertificate is null ? dn : caCertificate.IssuerDN)), caCertificate is null ? serial : caCertificate.SerialNumber));

            Asn1EncodableVector purposes = new Asn1EncodableVector();
            switch (mode)
            {
                case GenerateMode.CA:
                    certificateGenerator.AddExtension(X509Extensions.KeyUsage, false, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
                    certificateGenerator.AddExtension(X509Extensions.BasicConstraints, false, new BasicConstraints(true));
                    break;
                case GenerateMode.CLIENT:
                    certificateGenerator.AddExtension(X509Extensions.KeyUsage, false, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.NonRepudiation | KeyUsage.KeyEncipherment));
                    certificateGenerator.AddExtension(X509Extensions.BasicConstraints, false, new BasicConstraints(false));

                    purposes.Add(KeyPurposeID.id_kp_clientAuth);
                    certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, false, new DerSequence(purposes));
                    break;
                case GenerateMode.SERVER:
                    certificateGenerator.AddExtension(X509Extensions.KeyUsage, false, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.NonRepudiation | KeyUsage.KeyEncipherment));
                    certificateGenerator.AddExtension(X509Extensions.BasicConstraints, false, new BasicConstraints(false));

                    purposes.Add(KeyPurposeID.id_kp_serverAuth);
                    certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, false, new DerSequence(purposes));
                    break;
            }

            List<GeneralName> generalNames = new List<GeneralName>();
            if (alternativeNames is not null)
            {
                foreach (string name in alternativeNames)
                    generalNames.Add(new GeneralName(GeneralName.DnsName, name));
            }

            if (alternativeAddresses is not null)
            {
                foreach (string address in alternativeAddresses)
                    generalNames.Add(new GeneralName(GeneralName.IPAddress, address));
            }

            if (generalNames.Count > 0)
            {
                GeneralNames subjectAlternativeNames = new GeneralNames(generalNames.ToArray());
                certificateGenerator.AddExtension(X509Extensions.SubjectAlternativeName, false, subjectAlternativeNames);
            }

            ISignatureFactory signatureFactory;
            X509Certificate certificate;
            switch (mode)
            {
                case GenerateMode.CA:
                    signatureFactory = new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(), privateKey);
                    certificate = certificateGenerator.Generate(signatureFactory);
                    SignCertificate(certificate, publicKey);
                    break;
                default:
                    ArgumentNullException.ThrowIfNull(caCertificate);
                    signatureFactory = new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(), caPrivateKey);
                    certificate = certificateGenerator.Generate(signatureFactory);
                    SignCertificate(certificate, caCertificate.GetPublicKey());
                    break;
            }            

            Console.WriteLine(certificate);

            FileInfo certificateFileInfo = new FileInfo(certificateFile);
            if (certificateFileInfo.Directory is not null && !certificateFileInfo.Directory.Exists)
                certificateFileInfo.Directory.Create();
            using FileStream certificateStream = new FileStream(certificateFileInfo.FullName, FileMode.Create, FileAccess.Write);
            certificateStream.Write(certificate.GetEncoded());
            Console.WriteLine($"Certificate File Write : {certificateFileInfo.FullName}");

            return certificate;
        }

        private static readonly AtomicInt64 serialNumber = new AtomicInt64(DateTime.Now.ToMilliseconds());

        private static void SignCertificate(X509Certificate certificate, ICipherParameters pubKey)
        {
            byte[] tbsCert = certificate.GetTbsCertificate();
            byte[] signature = certificate.GetSignature();

            ISigner signer = SignerUtilities.GetSigner(certificate.SigAlgName);
            signer.Init(false, pubKey);
            signer.BlockUpdate(tbsCert, 0, tbsCert.Length);
        }

        private static void GenerateCertificateStore(string alias, AsymmetricKeyParameter privateKey, string storeFile, string storePassword, SecureRandom secureRandom, params X509Certificate[] certificate)
        {
            X509CertificateEntry[] entryArray = new X509CertificateEntry[certificate.Length];
            for (int index = 0; index < entryArray.Length; index++)
                entryArray[index] = new X509CertificateEntry(certificate[index]);

            Pkcs12Store store = new Pkcs12StoreBuilder().Build();
            store.SetKeyEntry(alias, new AsymmetricKeyEntry(privateKey), entryArray);

            FileInfo storeFileInfo = new FileInfo(storeFile);
            if (storeFileInfo.Directory is not null && !storeFileInfo.Directory.Exists)
                storeFileInfo.Directory.Create();
            using FileStream pkcs12Stream = new FileStream(storeFileInfo.FullName, FileMode.Create, FileAccess.Write);
            store.Save(pkcs12Stream, storePassword.ToCharArray(), secureRandom);
            Console.WriteLine($"PKCS12 Store File Write : {storeFileInfo.FullName}");
        }

        private static async Task GenerateServerCertificate(CmdMain cmdMain)
        {
            YamlDotNet.Serialization.Deserializer deserializer = new YamlDotNet.Serialization.Deserializer();
            string str = File.ReadAllText(cmdMain.ConfigFilePath);
            ServerCertificateConfiguration configuration = deserializer.Deserialize<ServerCertificateConfiguration>(str);
            ConfigurationValidator.Validate(configuration);
            ArgumentNullException.ThrowIfNull(configuration.KeySize);
            ArgumentNullException.ThrowIfNull(configuration.Days);

            SecureRandom secureRandom = new SecureRandom();

            GenerateKey(configuration.KeySize.Value, configuration.KeyFile, secureRandom, out AsymmetricCipherKeyPair keyPair, out PrivateKeyInfo privateKeyInfo, out SubjectPublicKeyInfo subjectPublicKeyInfo);
            X509Name dn = GenerateDN(configuration);

            FileInfo caStoreFileInfo = new FileInfo(configuration.CAStoreFile);
            if (caStoreFileInfo.Directory is not null && !caStoreFileInfo.Directory.Exists)
                caStoreFileInfo.Directory.Create();
            using FileStream caStoreStream = new FileStream(caStoreFileInfo.FullName, FileMode.Open, FileAccess.Read);
            Pkcs12Store caStore = new Pkcs12StoreBuilder().Build();
            caStore.Load(caStoreStream, configuration.CAStorePassword.ToCharArray());

            X509CertificateEntry caCertificateEntry = caStore.GetCertificate(caStore.Aliases.First());
            AsymmetricKeyParameter caPrivateKey = LoadPrivateKey(configuration.CAKeyFile);

            X509Certificate certificate = GenerateCertificate(dn, configuration.Days.Value, keyPair.Public, subjectPublicKeyInfo, keyPair.Private, configuration.CertificateFile, GenerateMode.SERVER, alternativeNames: configuration.AlternativeNames, alternativeAddresses: configuration.AlternativeAddresses, caPrivateKey: caPrivateKey, caCertificateEntry.Certificate);

            GenerateCertificateStore(configuration.Alias, keyPair.Private, configuration.StoreFile, configuration.StorePassword, secureRandom, configuration.WithCA.HasValue && configuration.WithCA.Value ? new X509Certificate[] { certificate, caCertificateEntry.Certificate } : new X509Certificate[] { certificate });

            await Task.CompletedTask;
        }

        private static AsymmetricKeyParameter LoadPrivateKey(string keyFile)
        {
            FileInfo keyFileInfo = new FileInfo(keyFile);
            if (keyFileInfo.Directory is not null && !keyFileInfo.Directory.Exists)
                keyFileInfo.Directory.Create();
            using (FileStream stream = new FileStream(keyFileInfo.FullName, FileMode.Open, FileAccess.Read)) 
            {
                using StreamReader reader = new StreamReader(stream);
                using PemReader pemReader = new PemReader(reader);
                PemObject pemObject = pemReader.ReadPemObject();
                switch (pemObject.Type)
                {
                    case "RSA PRIVATE KEY":
                        RsaPrivateKeyStructure rsaPrivateKeyStructure = RsaPrivateKeyStructure.GetInstance(pemObject.Content);
                        PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance), rsaPrivateKeyStructure);
                        return PrivateKeyFactory.CreateKey(privateKeyInfo);
                    default:
                        return PrivateKeyFactory.CreateKey(pemObject.Content);
                }
            }
        }

        private static async Task GenerateClientCertificate(CmdMain cmdMain)
        {
            YamlDotNet.Serialization.Deserializer deserializer = new YamlDotNet.Serialization.Deserializer();
            string str = File.ReadAllText(cmdMain.ConfigFilePath);
            ClientCertificateConfiguration configuration = deserializer.Deserialize<ClientCertificateConfiguration>(str);
            ConfigurationValidator.Validate(configuration);
            ArgumentNullException.ThrowIfNull(configuration.KeySize);
            ArgumentNullException.ThrowIfNull(configuration.Days);

            SecureRandom secureRandom = new SecureRandom();

            GenerateKey(configuration.KeySize.Value, configuration.KeyFile, secureRandom, out AsymmetricCipherKeyPair keyPair, out PrivateKeyInfo privateKeyInfo, out SubjectPublicKeyInfo subjectPublicKeyInfo);
            X509Name dn = GenerateDN(configuration);

            FileInfo caStoreFileInfo = new FileInfo(configuration.CAStoreFile);
            if (caStoreFileInfo.Directory is not null && !caStoreFileInfo.Directory.Exists)
                caStoreFileInfo.Directory.Create();
            using FileStream caStoreStream = new FileStream(caStoreFileInfo.FullName, FileMode.Open, FileAccess.Read);
            Pkcs12Store caStore = new Pkcs12StoreBuilder().Build();
            caStore.Load(caStoreStream, configuration.CAStorePassword.ToCharArray());

            X509CertificateEntry caCertificateEntry = caStore.GetCertificate(caStore.Aliases.First());
            AsymmetricKeyParameter caPrivateKey = LoadPrivateKey(configuration.CAKeyFile);

            X509Certificate certificate = GenerateCertificate(dn, configuration.Days.Value, keyPair.Public, subjectPublicKeyInfo, keyPair.Private, configuration.CertificateFile, GenerateMode.CLIENT, alternativeNames: configuration.AlternativeNames, alternativeAddresses: configuration.AlternativeAddresses, caPrivateKey: caPrivateKey, caCertificateEntry.Certificate);

            GenerateCertificateStore(configuration.Alias, keyPair.Private, configuration.StoreFile, configuration.StorePassword, secureRandom, configuration.WithCA.HasValue && configuration.WithCA.Value ? new X509Certificate[] { certificate, caCertificateEntry.Certificate } : new X509Certificate[] { certificate });

            await Task.CompletedTask;
        }

        internal static void PrintVersion(TextWriter writer)
        {
            RevisionAttribute? revisionAttribute = typeof(RevisionAttribute).Assembly.GetCustomAttribute<RevisionAttribute>();
            if (revisionAttribute is not null)
                writer.WriteLine($"CertificateGenerator Revision: {revisionAttribute.Revision}");
        }

        internal sealed class CmdMain
        {
            [Option("mode", Default = "SERVER")]
            public GenerateMode Mode { get; set; }

            [Option("config", Required = true)]
            public string ConfigFilePath { get; set; } = string.Empty;
        }

        internal enum GenerateMode
        {
            CA, SERVER, CLIENT
        }
    }
}
