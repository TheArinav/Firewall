namespace FirewallService.ipc.structs;

public struct Response() : IMessageComponent<Response>
{
    public bool OperationSuccessful { get; set; } = false;
    public string Message { get; set; } = "Null";
    public object? DBObject { get; set; } = null;

    public string ToStringStream()
    {
        throw new NotImplementedException();
    }

    public Response Get()
    {
        return this;
    }
}