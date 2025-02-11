using System.Text;
using FirewallService.auth;
using FirewallService.ipc.structs;

namespace FirewallService.ipc;
using System.Security;
using System.Security.Cryptography;
public class EncryptionManager
{
    private static Dictionary<long, SecureString> SessionKeys { get; set; } = new Dictionary<long, SecureString>();

    public static (string nonce, long timestamp, string decrypted) DecryptMessageComponent(long senderPID, MessageType type, string raw)
{
    string decryptedMessage;
    
    switch (type)
    {
        case MessageType.Init:
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

        case MessageType.Request:
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

    // Extract Nonce and Timestamp from decrypted string
    var components = decryptedMessage.Split('|');
    if (components.Length < 3)
        throw new FormatException("Invalid decrypted message format.");

    var nonce = components[0];
    var timestamp = long.Parse(components[1]);
    var content = components[2];

    return (nonce, timestamp, content);
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