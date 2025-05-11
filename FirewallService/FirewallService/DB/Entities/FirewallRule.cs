using System.Text.Json;

namespace FirewallService.DB.Entities;

public class FirewallRule : IDataBaseEntity<FirewallRule>
{
    public string RuleID { get; set; }
    public bool ActiveStatus { get; set; }
    public string ConnectionClassID { get; set; }
    public string ProtocolID { get; set; }
    public bool IsActive { get; set; }

    // Navigation properties
    public ConnectionClass ConnectionClass { get; set; }
    public Protocol Protocol { get; set; }
    public ICollection<Record> Records { get; set; }
    
    
    public string ToStringStream()
    {
        return JsonSerializer.Serialize(this);
    }

    public FirewallRule Get()
    {
        return this;
    }
}
