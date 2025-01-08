namespace FirewallService.util;
using System.Runtime.InteropServices;

public static class UtilityMethods
{
    public static string SerializeNumber(IConvertible? number)
    {
        if (!IsNumericType(number))
            throw new ArgumentException("Value must be a recognized numeric type!");
        var hexDigits = Marshal.SizeOf(number) * 2;
        var longValue = Convert.ToInt64(number);
        var hexString = longValue.ToString("X");
        return hexString.PadLeft(hexDigits, '0');
    }
    
    public static IConvertible DeserializeNumber(string hexString)
    {
        if (string.IsNullOrEmpty(hexString))
            throw new ArgumentException("Hex string cannot be null or empty");

        var len = hexString.Length;
        hexString = hexString.TrimStart('0');
        
        return (len switch
        {
            2 => Convert.ToByte(hexString, 16),
            4 => Convert.ToInt16(hexString, 16),
            8 => Convert.ToInt32(hexString, 16),
            16 => Convert.ToInt64(hexString, 16),
            _ => throw new ArgumentException("Invalid hex string length for supported numeric types")
        }) as IConvertible;
    }

    
    public static bool IsNumericType(object? obj)
    {
        if (obj == null) return false;
        var typeCode = Type.GetTypeCode(obj.GetType());
        return typeCode is TypeCode.Byte or TypeCode.SByte or TypeCode.UInt16 or TypeCode.UInt32 or TypeCode.UInt64 or TypeCode.Int16 or TypeCode.Int32 or TypeCode.Int64 or TypeCode.Decimal or TypeCode.Double or TypeCode.Single;
    }

}