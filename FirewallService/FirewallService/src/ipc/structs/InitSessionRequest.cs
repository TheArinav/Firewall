using FirewallService.auth.structs;
using System.Text;

namespace FirewallService.ipc.structs;

public class InitSessionRequest : IMessageComponent<InitSessionRequest>
{
    public const int AES_KEY_SIZE = 32; // Size in bytes
    public byte[] AESKey { get; set; }
    public AuthorizedUser Requester { get; set; }

    public InitSessionRequest()
    {
    }

    public InitSessionRequest(byte[] key, AuthorizedUser req)
    {
        this.AESKey = key;
        this.Requester = req;
    }

    public string ToStringStream()
    {
        var hex = BitConverter.ToString(this.AESKey).Replace("-", "");
        return $"[{hex}:{Requester.ToStringStream()}]";
    }

    public static InitSessionRequest Parse(string sStream)
    {
        try
        {
            var keySection = sStream[..(AES_KEY_SIZE * 2)];
            
            var key = Enumerable.Range(0, AES_KEY_SIZE)
                .Select(i => Convert.ToByte(keySection[(i*2)..(i*2+2)], 16)).ToArray(); 
            var usr = sStream[65..];
            var req = AuthorizedUser.Parse(usr);
            return new(key, req);
        }
        catch (Exception e)
        {
            throw new FormatException($"Invalid init request: {e.Message}");
        }
    }

    public InitSessionRequest Get()
    {
        return this;
    }
}
