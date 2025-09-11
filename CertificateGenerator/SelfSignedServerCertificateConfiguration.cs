using System.Configuration.Annotation;

namespace CertificateGenerator
{
    public class SelfSignedServerCertificateConfiguration : Configuration
    {
        [Property(PropertyType.INT, DefaultValue = "3650")]
        public override int? Days { get; set; }

        [Property(PropertyType.STRING, required: true)]
        public string KeyFile { get; set; } = string.Empty;

        [Property(PropertyType.STRING, required: true)]
        public string CertificateFile { get; set; } = string.Empty;

        [Property(PropertyType.STRING, required: true)]
        public string StoreFile { get; set; } = string.Empty;

        [Property(PropertyType.STRING, required: true)]
        public string StorePassword { get; set; } = string.Empty;

        [Property(PropertyType.STRING, required: false, DefaultValue = "selfsigned-server")]
        public virtual string Alias { get; set; } = string.Empty;
    }
}

