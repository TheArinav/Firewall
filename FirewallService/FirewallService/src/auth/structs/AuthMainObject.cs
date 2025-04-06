namespace FirewallService.auth.structs;
using System.Text;
public class AuthMainObject
{
    private List<UserConnection> _usersConnections = [];
    public AuthorizedUser[] Users { get; set; } = [];

    public UserConnection? InitUserConnection(AuthorizedUser usr, byte[] key)
    {
        var auth = (from user in Users where user.ID == usr.ID select 
                PasswordHasher.VerifyPassword(usr.Key,user.Key)).FirstOrDefault();

        if (!auth)
            return null;

        _usersConnections ??= [];

        if (_usersConnections.Any(conn => conn.User.ID == usr.ID))
            return null;

        var newConn = new UserConnection(new AuthorizedUserSession(usr.ID), key);
        _usersConnections.Add(newConn);
        return new UserConnection(_usersConnections[^1]);
    }

    public void Disconnect(long id)
    {
        var i = _usersConnections.TakeWhile(cur => cur.User.ID != id).Count();
        _usersConnections.RemoveAt(i);
    }
}
    
