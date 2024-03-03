using System.Configuration.Attributes;

namespace CertificateGenerator
{
    public sealed class ServerCertificateConfiguration : Configuration
    {
        [Property(PropertyAttribute.PropertyType.INT, DefaultValue = "3650")]
        public override int? Days { get; set; }

        [Property(PropertyAttribute.PropertyType.STRING, required: true)]
        public string KeyFile { get; set; } = string.Empty;

        [Property(PropertyAttribute.PropertyType.STRING, required: true)]
        public string CertificateFile { get; set; } = string.Empty;

        [Property(PropertyAttribute.PropertyType.STRING, required: true)]
        public string StoreFile { get; set; } = string.Empty;

        [Property(PropertyAttribute.PropertyType.STRING, required: true)]
        public string StorePassword { get; set; } = string.Empty;

        [Property(PropertyAttribute.PropertyType.STRING, required: false, DefaultValue = "server")]
        public string Alias { get; set; } = string.Empty;

        [Property(PropertyAttribute.PropertyType.STRING, required: true)]
        public string CAStoreFile { get; set; } = string.Empty;

        [Property(PropertyAttribute.PropertyType.STRING, required: true)]
        public string CAStorePassword { get; set; } = string.Empty;

        [Property(PropertyAttribute.PropertyType.STRING, required: true)]
        public string CAKeyFile { get; set; } = string.Empty;

        [Property(PropertyAttribute.PropertyType.BOOL, DefaultValue = "false")]
        public bool? WithCA { get; set; }
    }
}
