using System.Configuration.Annotation;

namespace CertificateGenerator
{
    public class ServerCertificateConfiguration : Configuration
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

        [Property(PropertyType.STRING, required: false, DefaultValue = "server")]
        public virtual string Alias { get; set; } = string.Empty;

        [Property(PropertyType.STRING, required: true)]
        public string CAStoreFile { get; set; } = string.Empty;

        [Property(PropertyType.STRING, required: true)]
        public string CAStorePassword { get; set; } = string.Empty;

        [Property(PropertyType.STRING, required: true)]
        public string CAKeyFile { get; set; } = string.Empty;

        [Property(PropertyType.BOOL, DefaultValue = "false")]
        public bool? WithCA { get; set; }
    }
}
