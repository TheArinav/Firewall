using System.Text.Json;

namespace FirewallService.DB.Entities;

public class TCPStateEnforcer : IDataBaseEntity<TCPStateEnforcer>
{
    public string EnforcerID { get; set; }
    public bool IsActive { get;set; }
    
    // Navigation Property
    public Enforcer Enforcer { get; set; }

    public string ToStringStream()
    {
        return JsonSerializer.Serialize(this);
    }

    public TCPStateEnforcer Get()
    {
        return this;
    }
}