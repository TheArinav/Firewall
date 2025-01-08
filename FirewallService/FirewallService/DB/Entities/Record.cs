namespace FirewallService.DB.Entities;
public class Record
{
    public string RecordID { get; set; }
    public bool Verdict { get; set; }
    public DateTime Timestamp { get; set; }
    public string PacketID { get; set; }
    public string RuleID { get; set; }

    // Navigation properties
    public Packet Packet { get; set; }
    public FirewallRule FirewallRule { get; set; }
}
