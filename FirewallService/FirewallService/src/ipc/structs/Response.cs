using System.Security.Cryptography;
using System.Text;
using FirewallService.DB.Entities;

namespace FirewallService.ipc.structs;

public struct Response : IMessageComponent<Response>, IMessageComponent<object>
{
    private IMessageComponent<object>? _messageComponentImplementation;
    public bool OperationSuccessful { get; set; } = false;
    public string Message { get; set; } = "Null";
    public IDataBaseEntity<object>? DBObject { get; set; } = null;
    public byte[]? Key { get; set; } = null;
    public string Nonce { get; set; }   // Fresh nonce for each response
    public long Timestamp { get; set; } // Prevent replay attacks

    public Response(bool operationSuccessful, string message, IDataBaseEntity<object>? dbObject, byte[] key)
    {
        OperationSuccessful = operationSuccessful;
        Message = message;
        DBObject = dbObject;
        Key = key;
        Nonce = GenerateNonce();
        Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    }

    public string ToStringStream()
    {
        var raw = $"{{{OperationSuccessful},'{Message}',{DBObject?.ToStringStream() ?? "null"},{Nonce},{Timestamp}}}";

        if (Key == null || Key.Length == 0) return raw;

        return Encrypt(raw, Key);
    }

    private static string GenerateNonce()
    {
        byte[] nonceBytes = new byte[16];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(nonceBytes);
        return Convert.ToBase64String(nonceBytes);
    }

    private static string Encrypt(string plainText, byte[] key)
    {
            // Ensure the AES key length is valid (128, 192, or 256 bits)
            if (key.Length != 16 && key.Length != 24 && key.Length != 32)    
                throw new ArgumentException("Invalid AES key length."); 
            using var aes = Aes.Create();    aes.Key = key;  
            // Generate a new IV for each encryption
            aes.GenerateIV();    // Encrypt the data
            using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);  
            var plainBytes = Encoding.UTF8.GetBytes(plainText); 
            var cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);    // Combine IV and ciphertext for later decryption
            var combinedBytes = new byte[aes.IV.Length + cipherBytes.Length]; 
            Array.Copy(aes.IV, 0, combinedBytes, 0, aes.IV.Length); // Copy IV to the beginning
            Array.Copy(cipherBytes, 0, combinedBytes, aes.IV.Length, cipherBytes.Length); // Append ciphertext
            // Return as a base64 string
            return Convert.ToBase64String(combinedBytes);
    }

    public Response Get()
    {
        return this;
    }

    object IMessageComponent<object>.Get()
    {
        return Get();
    }
}
