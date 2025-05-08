namespace FirewallService.auth.structs;
using System.Text;
public class AuthMainObject
{
    public List<UserConnection> UsersConnections = [];
    public AuthorizedUser[] Users { get; set; } = [];

    public UserConnection? InitUserConnection(AuthorizedUser usr, byte[] key)
    {
        var auth = (from user in Users where user.ID == usr.ID select 
                PasswordHasher.VerifyPassword(usr.Key.ToCharArray(),user.Key)).FirstOrDefault();

        if (!auth)
            return null;

        UsersConnections ??= [];

        if (UsersConnections.Any(conn => conn.User.ID == usr.ID))
            return null;

        var newConn = new UserConnection(new AuthorizedUserSession(usr.ID), key);
        UsersConnections.Add(newConn);
        return new UserConnection(UsersConnections[^1]);
    }

    public void Disconnect(long id)
    {
        var i = UsersConnections.TakeWhile(cur => cur.User.ID != id).Count();
        UsersConnections.RemoveAt(i);
    }

    public AuthorizedUser? GetUser(long ID)
    {
        foreach (var usr in this.Users)
            if (usr.ID == ID)
                return usr;
        return null;
    }
}
    
