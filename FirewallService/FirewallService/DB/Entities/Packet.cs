namespace FirewallService.DB.Entities;
public class Packet
{
    public string PacketID { get; set; }
    public bool IPversion { get; set; }
    public byte[] QoS { get; set; }
    public int Checksum { get; set; }
    public byte[] Payload { get; set; }
    public string Source { get; set; }
    public string Destination { get; set; }

    // Navigation properties
    public Connection SourceConnection { get; set; }
    public Connection DestinationConnection { get; set; }
}
