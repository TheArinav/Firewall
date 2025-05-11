using System.Text.Json;

namespace FirewallService.DB.Entities;
public class RateLimitEnforcer : IDataBaseEntity<RateLimitEnforcer>
{
    public string EnforcerID { get; set; }
    public int MaxPacketsPerSecond { get; set; }
    public bool IsActive { get; set; }

    // Navigation property
    public Enforcer Enforcer { get; set; }

    public string ToStringStream()
    {
        return JsonSerializer.Serialize(this);
    }

    public RateLimitEnforcer Get()
    {
        return this;
    }
}
