using FirewallService.auth.structs;
using FirewallService.DB.Entities;
using FirewallService.util;
using FirewallService.ipc.structs.GeneralActionStructs;

namespace FirewallService.ipc.structs;

public struct GeneralActionRequest : IMessageComponent<GeneralActionRequest>
{
    public AuthorizedUserSession Requester { get; set; }
    public string RequestBody { get; set; }

    public GeneralActionRequest()
    {
        this.Requester = default;
        this.RequestBody = "";
    }

    public string ToStringStream()
    {
        return $"[{this.Requester.ToStringStream()}:{this.RequestBody}]";
    }

    public static GeneralActionRequest Parse(string sStream)
    {
        var res = new GeneralActionRequest();
        if (sStream[0] != '[' || sStream[^1] != ']' || !sStream.Contains(':'))
            goto Fail;
        sStream = sStream.Replace("[", "").Replace("]", "");
        var (requester, query) = sStream.Contains(':') 
            ? (sStream[..sStream.IndexOf(':')], sStream[(sStream.IndexOf(':') + 1)..]) 
            : throw new FormatException("String must contain a ':' separator.");
        try
        {
            res.Requester = AuthorizedUserSession.Parse(requester);
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

    public GeneralActionRequest Get()
    {
        return this;
    }

    public GeneralAction? GetAction()
    {
        return GeneralAction.Deserialize(RequestBody);
    }
}