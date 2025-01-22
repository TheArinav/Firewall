using FirewallService.DB.Entities;

namespace FirewallService.ipc.structs;

public struct Response() : IMessageComponent<Response>, IMessageComponent<object>
{
    private IMessageComponent<object>? _messageComponentImplementation;
    public bool OperationSuccessful { get; set; } = false;
    public string Message { get; set; } = "Null";
    public IDataBaseEntity<object>? DBObject { get; set; } = null;
    public byte[]? Key { get; set; } = null;

    public Response(bool operationSuccessful, string message, IDataBaseEntity<object>? dbObject, byte[] key) : this()
    {
        OperationSuccessful = operationSuccessful;
        Message = message;
        DBObject = dbObject;
        Key = key;
    }

    public string ToStringStream()
    {
        var raw = $"{{{OperationSuccessful},'{Message}',{DBObject?.ToStringStream()??"null"}}}";
        // TODO: Encrypt with key
        return raw;
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