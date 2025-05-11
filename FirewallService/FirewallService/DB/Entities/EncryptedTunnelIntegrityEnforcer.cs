using System.Text.Json;

namespace FirewallService.DB.Entities;

public class EncryptedTunnelIntegrityEnforcer : IDataBaseEntity<EncryptedTunnelIntegrityEnforcer>
{
    public string EnforcerID { get; set; }
    public string TunnelType { get; set; }
    public bool IsActive { get; set; }

    // Navigation property
    public Enforcer Enforcer { get; set; }

    public string ToStringStream()
    {
        return JsonSerializer.Serialize(this);
    }

    public EncryptedTunnelIntegrityEnforcer Get()
    {
        return this;
    }
}