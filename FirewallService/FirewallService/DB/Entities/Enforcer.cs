namespace FirewallService.DB.Entities;

public class Enforcer
{
    public string EnforcerID { get; set; }

    // Navigation properties
    public ICollection<PayloadLengthEnforcer> PayloadLengthEnforcers { get; set; }
    public ICollection<Protocol> Protocols { get; set; }
}
