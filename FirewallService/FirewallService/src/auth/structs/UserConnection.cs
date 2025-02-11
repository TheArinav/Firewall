using System.Globalization;
namespace FirewallService.auth.structs;

public class UserConnection
{
    public const int AESKeySize = 32;  // Size in bytes
    public AuthorizedUser User;
    public byte[] Key;

    public UserConnection(AuthorizedUser User, byte[] Key)
    {
        if (Key.Length != AESKeySize)
            throw new ArgumentException($"Invalid AES key size. Expected {AESKeySize}; Got {Key.Length}");
        this.User = User;
        this.Key = Key;
    }

    public UserConnection(UserConnection conn)
    {
        this.User = new AuthorizedUser(conn.User.ID, (string)conn.User.Key.Clone());
        this.Key = (byte[])conn.Key.Clone();
    }
}