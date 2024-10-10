namespace FirewallService.DB.Entities;
public class Protocol
{
    public string ProtocolID { get; set; }
    public string ProtocolName { get; set; }
    public string EnforcerID { get; set; }

    // Navigation properties
    public Enforcer Enforcer { get; set; }
    public ICollection<FirewallRule> FirewallRules { get; set; }
}
