using System.Configuration.Attributes;

namespace CertificateGenerator
{
    public sealed class CaCertificateConfiguration : Configuration
    {
        [Property(PropertyAttribute.PropertyType.INT, DefaultValue = "7300")]
        public override int? Days { get; set; }

        [Property(PropertyAttribute.PropertyType.STRING, required: true)]
        public string KeyFile { get; set; } = string.Empty;

        [Property(PropertyAttribute.PropertyType.STRING, required: true)]
        public string CertificateFile { get; set; } = string.Empty;

        [Property(PropertyAttribute.PropertyType.STRING, required: true)]
        public string StoreFile { get; set; } = string.Empty;

        [Property(PropertyAttribute.PropertyType.STRING, required: true)]
        public string StorePassword { get; set; } = string.Empty;

        [Property(PropertyAttribute.PropertyType.STRING, required: false, DefaultValue = "ca")]
        public string Alias { get; set; } = string.Empty;
    }
}
