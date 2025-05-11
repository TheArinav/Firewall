using System.Text.Json;

namespace FirewallService.DB.Entities;
public class EncryptedTunnelDetectionEnforcer : IDataBaseEntity<EncryptedTunnelDetectionEnforcer>
{
    public string EnforcerID { get; set; }
    public double MaxEntropy { get; set; }
    public bool IsActive { get; set; }

    // Navigation property
    public Enforcer Enforcer { get; set; }

    public string ToStringStream()
    {
        return JsonSerializer.Serialize(this);
    }

    public EncryptedTunnelDetectionEnforcer Get()
    {
        return this;
    }
}
