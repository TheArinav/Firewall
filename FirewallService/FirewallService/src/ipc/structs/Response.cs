using System.Data.SqlTypes;
using System.Security.Cryptography;
using System.Text;
using FirewallService.DB.Entities;
using FirewallService.ipc;
using FirewallService.util;

namespace FirewallService.ipc.structs;

public struct Response() : IMessageComponent<Response>, IMessageComponent<object>, INullable
{
    private IMessageComponent<object>? _messageComponentImplementation;
    public bool OperationSuccessful { get; set; } = false;
    public string Message { get; set; } = "Null";
    public IStreamableObject<object>[]? ResultObjects { get; set; } = null;
    public byte[]? Key { get; set; } = null;
    public string Nonce { get; set; }   // Fresh nonce for each response
    public long Timestamp { get; set; } // Prevent replay attacks

    public Response(bool operationSuccessful, string message, IStreamableObject<object>[]? resultObjects, byte[]? key) : this()
    {
        OperationSuccessful = operationSuccessful;
        Message = message;
        ResultObjects = resultObjects;
        Key = key;
        Nonce = EncryptionManager.GenerateNonce();  // Use EncryptionManager for nonce
        Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    }

    public string ToStringStream()
    {
        Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var dbObjects = ResultObjects == null ? "null" : ResultObjects.Select(obj => 
            obj.ToStringStream()).Aggregate((a, b) => $"{a},{b}");
        var raw = $"{{{OperationSuccessful},'{Message}',{dbObjects},{Nonce},{Timestamp}}}";

        // Delegate encryption to EncryptionManager
        return Key == null || Key.Length == 0 ? raw : EncryptionManager.EncryptMessageComponent(raw, Key);
    }

    public Response Get()
    {
        return this;
    }

    object IMessageComponent<object>.Get()
    {
        return Get();
    }

    public bool IsNull { get; }
}
