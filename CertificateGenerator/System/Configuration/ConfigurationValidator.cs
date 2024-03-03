namespace System.Configuration
{
    using Attributes;
    using Reflection;

    public static class ConfigurationValidator
    {
        public static void Validate<T>(T? config)
        {
            ArgumentNullException.ThrowIfNull(config);

            Type type = config.GetType();
            IEnumerable<PropertyInfo> properties = type.GetTypeInfo().GetProperties(BindingFlags.Public | BindingFlags.Instance);

            Dictionary<string, IProperty> d = [];
            foreach (PropertyInfo propertyInfo in properties)
            {
                PropertyAttribute? propertyAttribute = propertyInfo.GetCustomAttribute<PropertyAttribute>();
                if (propertyAttribute != null)
                    d.Add(propertyInfo.Name, IProperty.Of<T>(config, propertyInfo, propertyAttribute));
            }

            foreach (PropertyInfo propertyInfo in properties)
            {
                PropertyAttribute? propertyAttribute = propertyInfo.GetCustomAttribute<PropertyAttribute>();
                if (propertyAttribute is not null)
                {
                    IProperty self = d[propertyInfo.Name];
                    IProperty? parent = null;
                    if (!string.IsNullOrWhiteSpace(propertyAttribute.Parent))
                    {
                        if (!d.TryGetValue(propertyAttribute.Parent, out parent))
                            throw new InvalidOperationException($"parent config property '{propertyAttribute.Parent}' not found");
                    }

                    if (propertyAttribute.Required && !self.IsValuePresent && (parent is null || parent.IsValuePresent))
                        throw new InvalidOperationException($"config property '{propertyInfo.Name}' must be provided");

                    if (!propertyAttribute.Required && !string.IsNullOrWhiteSpace(propertyAttribute.DefaultValue) && !self.IsValuePresent && (parent is null || parent.IsValuePresent))
                    {
                        switch (propertyAttribute.Type)
                        {
                            case PropertyAttribute.PropertyType.BOOL:
                                propertyInfo.SetValue(config, bool.Parse(propertyAttribute.DefaultValue));
                                break;
                            case PropertyAttribute.PropertyType.BYTE:
                                propertyInfo.SetValue(config, byte.Parse(propertyAttribute.DefaultValue));
                                break;
                            case PropertyAttribute.PropertyType.SBYTE:
                                propertyInfo.SetValue(config, sbyte.Parse(propertyAttribute.DefaultValue));
                                break;
                            case PropertyAttribute.PropertyType.SHORT:
                                propertyInfo.SetValue(config, short.Parse(propertyAttribute.DefaultValue));
                                break;
                            case PropertyAttribute.PropertyType.USHORT:
                                propertyInfo.SetValue(config, ushort.Parse(propertyAttribute.DefaultValue));
                                break;
                            case PropertyAttribute.PropertyType.INT:
                                propertyInfo.SetValue(config, int.Parse(propertyAttribute.DefaultValue));
                                break;
                            case PropertyAttribute.PropertyType.UINT:
                                propertyInfo.SetValue(config, uint.Parse(propertyAttribute.DefaultValue));
                                break;
                            case PropertyAttribute.PropertyType.LONG:
                                propertyInfo.SetValue(config, long.Parse(propertyAttribute.DefaultValue));
                                break;
                            case PropertyAttribute.PropertyType.ULONG:
                                propertyInfo.SetValue(config, ulong.Parse(propertyAttribute.DefaultValue));
                                break;
                            case PropertyAttribute.PropertyType.DOUBLE:
                                propertyInfo.SetValue(config, double.Parse(propertyAttribute.DefaultValue));
                                break;
                            case PropertyAttribute.PropertyType.STRING:
                                propertyInfo.SetValue(config, propertyAttribute.DefaultValue);
                                break;
                        }
                    }
                }
            }

            IValidatableConfiguration? configuration = config as IValidatableConfiguration;
            if (configuration is not null && !configuration.Validate())
                throw new InvalidOperationException($"{nameof(config)} validate failed");
        }

        internal interface IProperty
        {
            bool IsValuePresent { get; }

            internal sealed class BoolProperty(bool? v) : IProperty
            {
                private readonly bool? v = v;

                public bool IsValuePresent => v.HasValue;
            }

            internal sealed class ByteProperty(byte? v) : IProperty
            {
                private readonly byte? v = v;

                public bool IsValuePresent => v.HasValue;
            }

            internal sealed class SByteProperty(sbyte? v) : IProperty
            {
                private readonly sbyte? v = v;

                public bool IsValuePresent => v.HasValue;
            }

            internal sealed class Int16Property(short? v) : IProperty
            {
                private readonly short? v = v;

                public bool IsValuePresent => v.HasValue;
            }

            internal sealed class UInt16Property(ushort? v) : IProperty
            {
                private readonly ushort? v = v;

                public bool IsValuePresent => v.HasValue;
            }

            internal sealed class Int32Property(int? v) : IProperty
            {
                private readonly int? v = v;

                public bool IsValuePresent => v.HasValue;
            }

            internal sealed class UInt32Property(uint? v) : IProperty
            {
                private readonly uint? v = v;

                public bool IsValuePresent => v.HasValue;
            }

            internal sealed class Int64Property(long? v) : IProperty
            {
                private readonly long? v = v;

                public bool IsValuePresent => v.HasValue;
            }

            internal sealed class UInt64Property(ulong? v) : IProperty
            {
                private readonly ulong? v = v;

                public bool IsValuePresent => v.HasValue;
            }

            internal sealed class DecimalProperty(decimal? v) : IProperty
            {
                private readonly decimal? v = v;

                public bool IsValuePresent => v.HasValue;
            }

            internal sealed class SingleProperty(float? v) : IProperty
            {
                private readonly float? v = v;

                public bool IsValuePresent => v.HasValue;
            }

            internal sealed class DoubleProperty(double? v) : IProperty
            {
                private readonly double? v = v;

                public bool IsValuePresent => v.HasValue;
            }

            internal sealed class StringProperty(string? v) : IProperty
            {
                private readonly string? v = v;

                public bool IsValuePresent => !string.IsNullOrWhiteSpace(v);
            }

            public static IProperty Of<T>(T obj, PropertyInfo propertyInfo, PropertyAttribute propertyAttribute)
            {
                switch (propertyAttribute.Type)
                {
                    case PropertyAttribute.PropertyType.BOOL:
                        return new BoolProperty((bool?)propertyInfo.GetValue(obj));
                    case PropertyAttribute.PropertyType.BYTE:
                        return new ByteProperty((byte?)propertyInfo.GetValue(obj));
                    case PropertyAttribute.PropertyType.SBYTE:
                        return new SByteProperty((sbyte?)propertyInfo.GetValue(obj));
                    case PropertyAttribute.PropertyType.SHORT:
                        return new Int16Property((short?)propertyInfo.GetValue(obj));
                    case PropertyAttribute.PropertyType.USHORT:
                        return new UInt16Property((ushort?)propertyInfo.GetValue(obj));
                    case PropertyAttribute.PropertyType.INT:
                        return new Int32Property((int?)propertyInfo.GetValue(obj));
                    case PropertyAttribute.PropertyType.UINT:
                        return new UInt32Property((uint?)propertyInfo.GetValue(obj));
                    case PropertyAttribute.PropertyType.LONG:
                        return new Int64Property((long?)propertyInfo.GetValue(obj));
                    case PropertyAttribute.PropertyType.ULONG:
                        return new UInt64Property((ulong?)propertyInfo.GetValue(obj));
                    case PropertyAttribute.PropertyType.DOUBLE:
                        return new DoubleProperty((double?)propertyInfo.GetValue(obj));
                    case PropertyAttribute.PropertyType.STRING:
                        return new StringProperty(propertyInfo.GetValue(obj) as string ?? string.Empty);
                    default:
                        throw new InvalidOperationException($"unknown property type '{propertyAttribute.Type}'");
                }
            }
        }
    }
}
