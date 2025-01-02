using System.Text;

namespace FirewallService.util;

public interface IStreamableObject<out T>
{
    public string ToStringStream();

    public virtual byte[] ToByteStream()
    {
        return (byte[])(ToStringStream().Select(c => (byte)c).ToArray<byte>());
    }

    public virtual T Parse(string sStream, Type? t = null)
    {
        t ??= typeof(T);
        throw new NotImplementedException();
    }

    public virtual T Parse(byte[] bStream)
    {
        return Parse(Encoding.UTF8.GetString(bStream));
    }
}