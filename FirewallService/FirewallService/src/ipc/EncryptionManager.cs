using System.Text;
using FirewallService.auth;
using FirewallService.ipc.structs;

namespace FirewallService.ipc;
using System.Security;
using System.Security.Cryptography;
public class EncryptionManager
{
    private static Dictionary<long, SecureString> SessionKeys { get; set; } = new Dictionary<long, SecureString>();

    public static string? DecryptMessageComponent(long senderPID, MessageType type, string raw)
    {
        switch (type)
        {
            case MessageType.Init:
                // Decrypt raw using the private key from FileManager.GetKeyBytes() with RSA
                using (var rsa = RSA.Create())
                {
                    var privateKeyBytes = FileManager.GetKeyBytes(FileManager.RSAKey);
                    rsa.ImportRSAPrivateKey(privateKeyBytes, out _);

                    var encryptedBytes = Convert.FromBase64String(raw);
                    var decryptedBytes = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.OaepSHA256);

                    return Encoding.UTF8.GetString(decryptedBytes);
                }

                break;
            case MessageType.Request:
            case MessageType.Response:
                // Find AES key in SessionKeys using the senderPID and decrypt with AES
                if (!SessionKeys.TryGetValue(senderPID, out var secureAesKey))
                {
                    throw new InvalidOperationException($"No AES key found for sender PID {senderPID}");
                }

                var aesKeyBytes = SecureStringToByteArray(secureAesKey);

                using (var aes = Aes.Create())
                {
                    aes.Key = aesKeyBytes;
                    aes.Mode = CipherMode.CBC;

                    var encryptedBytes = Convert.FromBase64String(raw);
                    var iv = encryptedBytes.Take(16).ToArray(); // First 16 bytes are the IV
                    var cipherText = encryptedBytes.Skip(16).ToArray();

                    aes.IV = iv;

                    using (var decryptor = aes.CreateDecryptor())
                    {
                        var decryptedBytes = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
                        return Encoding.UTF8.GetString(decryptedBytes);
                    }
                }

                break;
                case MessageType.Unset:
                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
        }
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