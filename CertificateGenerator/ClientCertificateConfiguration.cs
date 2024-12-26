using System.Configuration.Annotation;

namespace CertificateGenerator
{
    public sealed class ClientCertificateConfiguration : ServerCertificateConfiguration
    {
        [Property(PropertyType.INT, DefaultValue = "365")]
        public override int? Days { get; set; }

        [Property(PropertyType.STRING, required: false, DefaultValue = "client")]
        public override string Alias { get; set; } = string.Empty;
    }
}
