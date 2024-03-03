namespace System
{
    public static class DateTimeExtensions
    {
        internal static readonly DateTime BaseTime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Unspecified);

        public static long ToMilliseconds(this DateTime dateTime)
        {
            return (long)(dateTime.ToUniversalTime() - BaseTime).TotalMilliseconds;
        }
    }
}
