using System.Text.Json;

namespace FirewallService.DB.Entities;
public class TLSFingerprintEnforcer : IDataBaseEntity<TLSFingerprintEnforcer>
{
    public string EnforcerID { get; set; }
    public List<string> AllowedFingerprints { get; set; }

    // Navigation property
    public Enforcer Enforcer { get; set; }

    public string ToStringStream()
    {
        return JsonSerializer.Serialize(this);
    }

    public TLSFingerprintEnforcer Get()
    {
        return this;
    }
}
