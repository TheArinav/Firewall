namespace FirewallService.auth.structs;

public struct AuthorizedUser
{
    public long ID { get; set; }
    public string Key { get; set; }

    public AuthorizedUser()
    {
        this.ID = default;
        this.Key = "";
    }
}