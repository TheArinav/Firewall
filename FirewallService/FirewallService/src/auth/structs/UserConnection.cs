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
}