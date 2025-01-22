namespace FirewallService.auth.structs;

public struct AuthMainObject
{
    private List<UserConnection> _usersConnections = new();
    public AuthorizedUser[] Users { get; set; } = [];

    public AuthMainObject()
    {
    }

    public UserConnection? InitUserConnection(AuthorizedUser usr, byte[] key)
    {
        var auth = (from user in Users where user.ID == usr.ID select user.Key == usr.Key).FirstOrDefault();

        if (!auth)
            return null;

        _usersConnections ??= new();
        var newConn = new UserConnection(usr, key);
        _usersConnections.Add(newConn);
        return _usersConnections[^1];
    }

    
}
    
