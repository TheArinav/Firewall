using System.Text.Json;
using FirewallService.DB.util;

namespace FirewallService.DB.Entities;
public class RegexEnforcer : IDataBaseEntity<RegexEnforcer>
{
    public string EnforcerID { get; set; }
    public string Pattern { get; set; }
    public bool IsActive { get; set; }

    // Navigation property
    public Enforcer Enforcer { get; set; }

    public string ToStringStream()
    {
        return JsonSerializer.Serialize(this);
    }

    public RegexEnforcer Get()
    {
        return this;
    }
}
