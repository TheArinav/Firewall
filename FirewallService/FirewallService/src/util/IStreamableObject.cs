using System.Text;

namespace FirewallService.util;

public interface IStreamableObject<out T>
{
    public string ToStringStream();

    public byte[] ToByteStream()
    {
        return (byte[])(ToStringStream().Select(c => (byte)c).ToArray<byte>());
    }

    public static T Parse(string sStream)
    {
        throw new NotImplementedException();
    }

    public static T Parse(byte[] bStream)
    {
        return Parse(Encoding.UTF8.GetString(bStream));
    }
}