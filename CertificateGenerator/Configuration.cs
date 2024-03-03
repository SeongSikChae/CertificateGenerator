using System.Configuration.Attributes;

namespace CertificateGenerator
{
    public class Configuration
    {
        [Property(PropertyAttribute.PropertyType.INT, DefaultValue = "2048")]
        public int? KeySize { get; set; }

        [Property(PropertyAttribute.PropertyType.STRING, DefaultValue = "KR")]
        public string? CountryName { get; set; }

        [Property(PropertyAttribute.PropertyType.STRING)]
        public string? StateOrProvinceName { get; set; }

        [Property(PropertyAttribute.PropertyType.STRING)]
        public string? LocalityName { get; set; }

        [Property(PropertyAttribute.PropertyType.STRING)]
        public string? OrganizationName { get; set; }

        [Property(PropertyAttribute.PropertyType.STRING)]
        public string? OrganizationalUnitName { get; set; }

        [Property(PropertyAttribute.PropertyType.STRING, required: true)]
        public string CommonName { get; set; } = string.Empty;

        [Property(PropertyAttribute.PropertyType.STRING)]
        public string? Email { get; set; }

        [Property(PropertyAttribute.PropertyType.STRING)]
        public string? AlternativeNames { get; set; }

        [Property(PropertyAttribute.PropertyType.STRING)]
        public string? AlternativeAddresses { get; set; }

        [Property(PropertyAttribute.PropertyType.INT, DefaultValue = "3650")]
        public virtual int? Days { get; set; }
    }
}
