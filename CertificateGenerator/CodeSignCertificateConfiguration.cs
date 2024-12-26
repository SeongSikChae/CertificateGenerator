using System.Configuration.Annotation;

namespace CertificateGenerator
{
	public sealed class CodeSignCertificateConfiguration : ServerCertificateConfiguration
	{
		[Property(PropertyType.INT, DefaultValue = "365")]
		public override int? Days { get; set; }

		[Property(PropertyType.STRING, DefaultValue = "codesign")]
		public override string Alias { get; set; } = string.Empty;
	}
}
