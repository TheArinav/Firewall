namespace FirewallService.auth.structs;

public class UserConnection
{
    public const int AESKeySize = 256;
    public AuthorizedUser User;
    public byte[] Key;
    
}