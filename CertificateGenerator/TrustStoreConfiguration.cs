using System.Configuration.Annotation;

namespace CertificateGenerator
{
    public class TrustStoreConfiguration
    {
        [Property(PropertyType.STRING, required: true)]
        public string CertificateFiles { get; set; } = null!;

        [Property(PropertyType.STRING, required: true)]
        public string CertAliasList { get; set; } = null!;

        [Property(PropertyType.STRING, required: true)]
        public string StoreFile { get; set; } = null!;

        [Property(PropertyType.STRING, required: true)]
        public string StorePassword { get; set; } = null!;

        [Property(PropertyType.STRING, required: false, DefaultValue = "trust")]
        public string Alias { get; set; } = null!;
    }
}
