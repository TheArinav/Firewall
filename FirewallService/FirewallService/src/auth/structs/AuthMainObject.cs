namespace FirewallService.auth.structs;

public struct AuthMainObject
{
    public UserConnection[] Users { get; set; }

    public AuthMainObject()
    {
        Users = new UserConnection[] { };
    }
}