using FirewallService.auth.structs;
using System.Text;

namespace FirewallService.ipc.structs;

public class InitRequest : IMessageComponent<InitRequest>
{
    public const int AES_KEY_SIZE = 32;
    public byte[] AESKey { get; set; }
    public AuthorizedUser Requester { get; set; }

    public InitRequest()
    {
    }

    public InitRequest(byte[] key, AuthorizedUser req)
    {
        this.AESKey = key;
        this.Requester = req;
    }

    public string ToStringStream()
    {
        var hex = BitConverter.ToString(this.AESKey).Replace("-", "");
        return $"[{hex}:{Requester.ToStringStream()}]";
    }

    public static InitRequest Parse(string sStream)
    {
        try
        {
            var key = Encoding.ASCII.GetBytes(sStream.Substring(1, AES_KEY_SIZE));
            var req = AuthorizedUser.Parse(sStream[34..^1]);
            return new(key, req);
        }
        catch
        {
            throw new FormatException("Invalid init request");
        }
    }

    public InitRequest Get()
    {
        return this;
    }
}