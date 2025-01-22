using System.Text.Json;

namespace FirewallService.DB.Entities;

public class ConnectionClass : IDataBaseEntity<ConnectionClass>
{
    public string ClassID { get; set; }
    public string ClassName { get; set; }
    public string Description { get; set; }

    // Navigation property
    public ICollection<Connection> Connections { get; set; }
    
    public string ToStringStream()
    {
        return JsonSerializer.Serialize(this);
    }

    public ConnectionClass Get()
    {
        return this;
    }
}
