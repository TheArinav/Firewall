using System.Text.Json;

namespace FirewallService.DB.Entities;
public class IpPortEnforcer : IDataBaseEntity<IpPortEnforcer>
{
    public string EnforcerID { get; set; }
    public List<string> AllowedSources { get; set; }
    public List<string> AllowedDestinations { get; set; }
    public List<int> AllowedSourcePorts { get; set; }
    public List<int> AllowedDestinationPorts { get; set; }

    // Navigation property
    public Enforcer Enforcer { get; set; }

    public string ToStringStream()
    {
        return JsonSerializer.Serialize(this);
    }

    public IpPortEnforcer Get()
    {
        return this;
    }
}
