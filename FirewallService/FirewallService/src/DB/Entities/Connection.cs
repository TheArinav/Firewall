using System.Text.Json;
using FirewallService.DB.util;
using Microsoft.EntityFrameworkCore.Storage;


namespace FirewallService.DB.Entities;

public class Connection : IDataBaseEntity<Connection>
{
    public string ConnectionID { get; set; }
    public string IPv4Address { get; set; }
    public string IPv6Address { get; set; }
    public string Port { get; set; }
    public string ConnectionClassID { get; set; }
    
    public bool IsActive { get; set; }

    // Navigation properties
    public ConnectionClass ConnectionClass { get; set; }
    public ICollection<Packet> SourcePackets { get; set; }
    public ICollection<Packet> DestinationPackets { get; set; }
    public string ToStringStream()
    {
        return JsonSerializer.Serialize(this);
    }

    public Connection Get()
    {
        return this;
    }
}
