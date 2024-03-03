using CommandLine;
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
                            break;
                        case GenerateMode.SERVER:
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

            IAsymmetricCipherKeyPairGenerator generator = new RsaKeyPairGenerator();
            KeyGenerationParameters parameters = new KeyGenerationParameters(secureRandom, configuration.KeySize.Value);
            generator.Init(parameters);
            Console.WriteLine($"key pair generate... : {configuration.KeySize.Value}");
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            PemObject pemObject = new PemObject("PRIVATE KEY", privateKeyInfo.GetEncoded());
            FileInfo privateKeyFileInfo = new FileInfo(configuration.KeyFile);
            if (privateKeyFileInfo.Directory is not null && !privateKeyFileInfo.Directory.Exists)
                privateKeyFileInfo.Directory.Create();
            using (FileStream stream = new FileStream(privateKeyFileInfo.FullName, FileMode.Create, FileAccess.Write))
            {
                using StreamWriter writer = new StreamWriter(stream);
                using PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(pemObject);
            }
            Console.WriteLine($"Private Key File Write : {privateKeyFileInfo.FullName}");
            StringBuilder dnBuilder = new StringBuilder($"CN={configuration.CommonName}");
            if (configuration.OrganizationName is not null)
                dnBuilder.Append($", O={configuration.OrganizationName}");
            X509Name dn = new X509Name(dnBuilder.ToString());

            X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
            Org.BouncyCastle.Math.BigInteger serial = new Org.BouncyCastle.Math.BigInteger(serialNumber.Value.ToString());
            certificateGenerator.SetSerialNumber(serial);
            certificateGenerator.SetIssuerDN(dn);
            certificateGenerator.SetSubjectDN(dn);

            DateTime notBefore = DateTime.Now;
            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notBefore.AddDays(configuration.Days.Value));
            certificateGenerator.SetPublicKey(keyPair.Public);
            certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifier(subjectPublicKeyInfo));
            certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifier(subjectPublicKeyInfo, new GeneralNames(new GeneralName(dn)), serial));
            certificateGenerator.AddExtension(X509Extensions.KeyUsage, false, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
            certificateGenerator.AddExtension(X509Extensions.BasicConstraints, false, new BasicConstraints(true));

            ISignatureFactory signatureFactory = new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(), keyPair.Private);
            X509Certificate certificate = certificateGenerator.Generate(signatureFactory);
            Console.WriteLine(certificate);

            FileInfo certificateFileInfo = new FileInfo(configuration.CertificateFile);
            if (certificateFileInfo.Directory is not null && !certificateFileInfo.Directory.Exists)
                certificateFileInfo.Directory.Create();
            using FileStream certificateStream = new FileStream(certificateFileInfo.FullName, FileMode.Create, FileAccess.Write);
            certificateStream.Write(certificate.GetEncoded());
            Console.WriteLine($"Certificate File Write : {certificateFileInfo.FullName}");

            Pkcs12Store store = new Pkcs12StoreBuilder().Build();
            store.SetKeyEntry(configuration.Alias, new AsymmetricKeyEntry(keyPair.Private), new X509CertificateEntry[] { new X509CertificateEntry(certificate) });

            FileInfo storeFileInfo = new FileInfo(configuration.StoreFile);
            if (storeFileInfo.Directory is not null && !storeFileInfo.Directory.Exists)
                storeFileInfo.Directory.Create();
            using FileStream pkcs12Stream = new FileStream(configuration.StoreFile, FileMode.Create, FileAccess.Write);
            store.Save(pkcs12Stream, configuration.StorePassword.ToCharArray(), secureRandom);
            Console.WriteLine($"PKCS12 Store File Write : {storeFileInfo.FullName}");

            await Task.CompletedTask;
        }

        private static readonly AtomicInt64 serialNumber = new AtomicInt64(DateTime.Now.ToMilliseconds());

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
