namespace FirewallService.DB.Entities;

public class FirewallRule
{
    public string RuleID { get; set; }
    public bool ActiveStatus { get; set; }
    public string ConnectionClassID { get; set; }
    public string ProtocolID { get; set; }

    // Navigation properties
    public ConnectionClass ConnectionClass { get; set; }
    public Protocol Protocol { get; set; }
    public ICollection<Record> Records { get; set; }
}
