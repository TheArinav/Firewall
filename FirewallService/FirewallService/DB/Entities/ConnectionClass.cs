namespace FirewallService.DB.Entities;

public class ConnectionClass
{
    public string ClassID { get; set; }
    public string ClassName { get; set; }
    public string Description { get; set; }

    // Navigation property
    public ICollection<Connection> Connections { get; set; }
}
