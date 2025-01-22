using System.Text.Json;

namespace FirewallService.DB.Entities;

public class Enforcer : IDataBaseEntity<Enforcer>
{
    public string EnforcerID { get; set; }

    // Navigation properties
    public ICollection<PayloadLengthEnforcer> PayloadLengthEnforcers { get; set; }
    public ICollection<Protocol> Protocols { get; set; }
    
    public string ToStringStream()
    {
        return JsonSerializer.Serialize(this);
    }

    public Enforcer Get()
    {
        return this;
    }
}
