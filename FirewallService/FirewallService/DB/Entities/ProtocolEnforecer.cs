using System.Text.Json;

namespace FirewallService.DB.Entities;
public class ProtocolEnforcer : IDataBaseEntity<ProtocolEnforcer>
{
    public string EnforcerID { get; set; }
    public List<string> AllowedProtocols { get; set; }

    // Navigation property
    public Enforcer Enforcer { get; set; }

    public string ToStringStream()
    {
        return JsonSerializer.Serialize(this);
    }

    public ProtocolEnforcer Get()
    {
        return this;
    }
}
