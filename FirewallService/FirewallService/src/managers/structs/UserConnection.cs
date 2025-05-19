using System.Globalization;
namespace FirewallService.managers.structs;

public class UserConnection
{
    public const int AESKeySize = 32;  // Size in bytes
    public AuthorizedUserSession User;
    public SecureKey Key;

    public UserConnection(AuthorizedUserSession User, byte[] Key)
    {
        if (Key.Length != AESKeySize)
            throw new ArgumentException($"Invalid AES key size. Expected {AESKeySize}; Got {Key.Length}");
        this.User = User;
        this.Key = new SecureKey(true);
        try
        {
            var i = 0;
            foreach (var cur in Key)
                this.Key[i++] = cur;
        }
        finally
        {
            this.Key.Close();
        }
    }

    public UserConnection(UserConnection conn)
    {
        this.User = new AuthorizedUserSession(conn.User.ID, (SecureKey)conn.User.Token.Clone());
        this.Key = (SecureKey)conn.Key.Clone();
    }
}