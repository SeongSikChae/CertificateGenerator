using System.Configuration.Attributes;

namespace CertificateGenerator
{
    public sealed class ClientCertificateConfiguration : ServerCertificateConfiguration
    {
        [Property(PropertyAttribute.PropertyType.INT, DefaultValue = "365")]
        public override int? Days { get; set; }

        [Property(PropertyAttribute.PropertyType.STRING, required: false, DefaultValue = "client")]
        public override string Alias { get; set; } = string.Empty;
    }
}
