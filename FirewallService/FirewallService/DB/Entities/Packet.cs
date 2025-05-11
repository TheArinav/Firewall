using System.Text.Json;

namespace FirewallService.DB.Entities;
public class Packet : IDataBaseEntity<Packet>
{
    public string PacketID { get; set; }
    public bool IPversion { get; set; }
    public byte[] QoS { get; set; }
    public int Checksum { get; set; }
    public byte[] Payload { get; set; }
    public string Source { get; set; }
    public string Destination { get; set; }
    public bool IsActive { get; set; }

    // Navigation properties
    public Connection SourceConnection { get; set; }
    public Connection DestinationConnection { get; set; }
    
    public string ToStringStream()
    {
        return JsonSerializer.Serialize(this);
    }

    public Packet Get()
    {
        return this;
    }
}
