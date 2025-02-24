using System.Text.Json;

namespace FirewallService.DB.Entities;
public class FirewallRuleEnforcer :  IDataBaseEntity<FirewallRuleEnforcer>
{
    public string RuleID { get; set; }
    public string EnforcerID { get; set; }

    // Navigation properties
    public FirewallRule FirewallRule { get; set; }
    public Enforcer Enforcer { get; set; }
    public string ToStringStream()
    {
        return JsonSerializer.Serialize(this);
    }

    public FirewallRuleEnforcer Get()
    {
        return this;
    }
}
