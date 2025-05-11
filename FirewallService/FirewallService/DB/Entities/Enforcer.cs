using System.Text.Json;

namespace FirewallService.DB.Entities;

public class Enforcer : IDataBaseEntity<Enforcer>
{
    public string EnforcerID { get; set; }
    public bool IsActive { get; set; }

    // Navigation properties
    public ICollection<PayloadLengthEnforcer> PayloadLengthEnforcers { get; set; }
    public ICollection<EncryptedTunnelDetectionEnforcer> EncryptedTunnelDetectionEnforcers { get; set; }
    public ICollection<EncryptedTunnelIntegrityEnforcer> EncryptedTunnelIntegrityEnforcers { get; set; }
    public ICollection<RateLimitEnforcer> RateLimitEnforcers { get; set; }
    public ICollection<RegexEnforcer> RegexEnforcers { get; set; }
    public ICollection<TLSFingerprintEnforcer> TLSFingerprintEnforcers { get; set; }
    public ICollection<TCPStateEnforcer> TCPStateEnforcers { get; set; }
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
