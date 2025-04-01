using System.Text;
using FirewallService.auth;
using FirewallService.ipc.structs;

namespace FirewallService.ipc;
using System.Security;
using System.Security.Cryptography;

public class EncryptionManager
{
    private static Dictionary<long, SecureString> SessionKeys { get; set; } = new Dictionary<long, SecureString>();

    public static string EncryptMessageComponent(string plainText, byte[] key)
    {
        if (key.Length != 16 && key.Length != 24 && key.Length != 32)
            throw new ArgumentException("Invalid AES key length.");

        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV(); // Generate a fresh IV for each encryption

        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        var cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

        // Combine IV and ciphertext
        var combinedBytes = new byte[aes.IV.Length + cipherBytes.Length];
        Array.Copy(aes.IV, 0, combinedBytes, 0, aes.IV.Length);
        Array.Copy(cipherBytes, 0, combinedBytes, aes.IV.Length, cipherBytes.Length);

        return Convert.ToBase64String(combinedBytes);
    }

    public static (string nonce, long timestamp, string decrypted) DecryptMessageComponent(long senderPID, MessageType type, string raw)
    {
        string decryptedMessage;
        
        switch (type)
        {
            case MessageType.InitSessionRequest:
                using (var rsa = RSA.Create())
                {
                    var privateKeyBytes = FileManager.GetKeyBytes(FileManager.RSAKey);
                    int bRead = 0;
                    rsa.ImportPkcs8PrivateKey(privateKeyBytes, out bRead);

                    raw = raw.Trim().Replace("\n", "").Replace("\r", "");
                    var decryptedBytes = rsa.Decrypt(Convert.FromBase64String(raw), RSAEncryptionPadding.OaepSHA256);
                    decryptedMessage = Encoding.UTF8.GetString(decryptedBytes);
                }
                break;

            case MessageType.GeneralActionRequest:
            case MessageType.Response:
                if (!SessionKeys.TryGetValue(senderPID, out var secureAesKey))
                    throw new InvalidOperationException($"No AES key found for sender PID {senderPID}");

                var aesKeyBytes = SecureStringToByteArray(secureAesKey);

                using (var aes = Aes.Create())
                {
                    aes.Key = aesKeyBytes;
                    aes.Mode = CipherMode.CBC;

                    var encryptedBytes = Convert.FromBase64String(raw);
                    var iv = encryptedBytes.Take(16).ToArray();
                    var cipherText = encryptedBytes.Skip(16).ToArray();

                    aes.IV = iv;

                    using (var decryptor = aes.CreateDecryptor())
                    {
                        var decryptedBytes = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
                        decryptedMessage = Encoding.UTF8.GetString(decryptedBytes);
                    }
                }
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(type), type, null);
        }

        // Extract Nonce and Timestamp
        var components = decryptedMessage.Split('|');
        if (components.Length < 3)
            throw new FormatException("Invalid decrypted message format.");

        var nonce = components[0];
        var timestamp = long.Parse(components[1]);
        var content = components[2];

        return (nonce, timestamp, content);
    }

    public static string GenerateNonce()
    {
        byte[] nonceBytes = new byte[16];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(nonceBytes);
        return Convert.ToBase64String(nonceBytes);
    }

    private static byte[] SecureStringToByteArray(SecureString secureString)
    {
        ArgumentNullException.ThrowIfNull(secureString);

        var bstr = IntPtr.Zero;
        try
        {
            bstr = System.Runtime.InteropServices.Marshal.SecureStringToBSTR(secureString);
            var plainText = System.Runtime.InteropServices.Marshal.PtrToStringBSTR(bstr);
            return Convert.FromBase64String(plainText);
        }
        finally
        {
            if (bstr != IntPtr.Zero)
                System.Runtime.InteropServices.Marshal.ZeroFreeBSTR(bstr);
        }
    }
}
