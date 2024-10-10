namespace FirewallService.DB.Entities;

public class Connection
{
    public string ConnectionID { get; set; }
    public string IPv4Address { get; set; }
    public string IPv6Address { get; set; }
    public string Port { get; set; }
    public string ConnectionClassID { get; set; }

    // Navigation properties
    public ConnectionClass ConnectionClass { get; set; }
    public ICollection<Packet> SourcePackets { get; set; }
    public ICollection<Packet> DestinationPackets { get; set; }
}
