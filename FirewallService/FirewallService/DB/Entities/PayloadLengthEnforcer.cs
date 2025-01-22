using System.Text.Json;

namespace FirewallService.DB.Entities;

public class PayloadLengthEnforcer : IDataBaseEntity<PayloadLengthEnforcer>
{
    public int Maximum { get; set; }
    public int Minimum { get; set; }
    public string EnforcerID { get; set; }

    // Navigation property
    public Enforcer Enforcer { get; set; }
    
    public string ToStringStream()
    {
        return JsonSerializer.Serialize(this);
    }

    public PayloadLengthEnforcer Get()
    {
        return this;
    }
}
