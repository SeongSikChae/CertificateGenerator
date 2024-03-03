namespace System.Configuration.Attributes
{
    [AttributeUsage(AttributeTargets.Property, AllowMultiple = false)]
    public sealed class PropertyAttribute(PropertyAttribute.PropertyType propertyType, bool required = false) : Attribute
    {
        public PropertyType Type { get; } = propertyType;

        public bool Required { get; } = required;

        public string? Parent { get; set; }

        public string? DefaultValue { get; set; }

        public enum PropertyType
        {
            BOOL,
            BYTE,
            SBYTE,
            SHORT,
            USHORT,
            INT,
            UINT,
            LONG,
            ULONG,
            DOUBLE,
            STRING
        }
    }
}
