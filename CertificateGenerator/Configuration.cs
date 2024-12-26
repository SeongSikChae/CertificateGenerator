using System.Configuration.Annotation;

namespace CertificateGenerator
{
    public class Configuration
    {
        [Property(PropertyType.INT, DefaultValue = "2048")]
        public int? KeySize { get; set; }

        [Property(PropertyType.STRING, DefaultValue = "KR")]
        public string? CountryName { get; set; }

        [Property(PropertyType.STRING)]
        public string? StateOrProvinceName { get; set; }

        [Property(PropertyType.STRING)]
        public string? LocalityName { get; set; }

        [Property(PropertyType.STRING)]
        public string? OrganizationName { get; set; }

        [Property(PropertyType.STRING)]
        public string? OrganizationalUnitName { get; set; }

        [Property(PropertyType.STRING, required: true)]
        public string CommonName { get; set; } = string.Empty;

        [Property(PropertyType.STRING)]
        public string? Email { get; set; }

        public List<string> AlternativeNames { get; set; } = new List<string>();

        public List<string> AlternativeAddresses { get; set; } = new List<string>();

        [Property(PropertyType.INT, DefaultValue = "3650")]
        public virtual int? Days { get; set; }
    }
}
