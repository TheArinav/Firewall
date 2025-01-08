namespace FirewallService.DB.Entities;

public class PayloadLengthEnforcer
{
    public int Maximum { get; set; }
    public int Minimum { get; set; }
    public string EnforcerID { get; set; }

    // Navigation property
    public Enforcer Enforcer { get; set; }
}
