namespace FirewallService.auth.structs;

public struct AuthMainObject
{
    public AuthorizedUser[] Users { get; set; }

    public AuthMainObject()
    {
        Users = new AuthorizedUser[] { };
    }
}