using FirewallService.auth.structs;
using FirewallService.DB.Entities;
using FirewallService.util;

namespace FirewallService.ipc.structs;

public struct Request : IMessageComponent<Request>
{
    public AuthorizedUser Requester { get; set; }
    public string SQLQuery { get; set; }

    public Request()
    {
        this.Requester = default;
        this.SQLQuery = "";
    }

    public string ToStringStream()
    {
        return $"[{this.Requester.ToStringStream()}:{this.SQLQuery}]";
    }

    public static Request Parse(string sStream)
    {
        var res = new Request();
        if (sStream[0] != '[' || sStream[^1] != ']' || !sStream.Contains(':'))
            goto Fail;
        sStream = sStream.Replace("[", "").Replace("]", "");
        (string requester, string query) = sStream.Contains(':') 
            ? (sStream[..sStream.IndexOf(':')], sStream[(sStream.IndexOf(':') + 1)..]) 
            : throw new FormatException("String must contain a ':' separator.");
        try
        {
            res.Requester = AuthorizedUser.Parse(requester);
        }
        catch (FormatException e)
        {
            throw new FormatException($"Can't parse Request <= {e.Message}");
        }
        Fail:
        {
            throw new FormatException($"Can't parse '{sStream}' to Request");
        }
    }

    public Request Get()
    {
        return this;
    }
}