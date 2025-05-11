using System.Text.Json;

namespace FirewallService.DB.Entities;
public class Record : IDataBaseEntity<Record>
{
    public string RecordID { get; set; }
    public bool Verdict { get; set; }
    public DateTime Timestamp { get; set; }
    public string PacketID { get; set; }
    public string RuleID { get; set; }
    public bool IsActive { get; set; }

    // Navigation properties
    public Packet Packet { get; set; }
    public FirewallRule FirewallRule { get; set; }
    
    public string ToStringStream()
    {
        return JsonSerializer.Serialize(this);
    }

    public Record Get()
    {
        return this;
    }
}
