using System.Text.Json;
using FirewallService.DB.util;

namespace FirewallService.DB.Entities;
public class Protocol : IDataBaseEntity<Protocol>
{
    public string ProtocolID { get; set; }
    public string ProtocolName { get; set; }
    public bool ActiveStatus { get; set; }
    public string EnforcerID { get; set; }
    public bool IsActive { get; set; }

    // Navigation properties
    public Enforcer Enforcer { get; set; }
    public ICollection<FirewallRule> FirewallRules { get; set; }
    
    public string ToStringStream()
    {
        return JsonSerializer.Serialize(this);
    }

    public Protocol Get()
    {
        return this;
    }
}
