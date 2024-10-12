using FirewallService.auth.structs;

namespace FirewallService.ipc.structs;

public struct Request : IMessageComponent
{
    public AuthorizedUser Requester { get; set; }
    public string SQLQuery { get; set; }

    public Request()
    {
        this.Requester = default;
        this.SQLQuery = "";
    }
}