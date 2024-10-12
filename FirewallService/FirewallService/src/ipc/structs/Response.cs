namespace FirewallService.ipc.structs;

public struct Response : IMessageComponent
{
    public bool OperationSuccessful { get; set; }
    public object DBObject { get; set; }

    public Response()
    {
        this.OperationSuccessful = false;
        this.DBObject = null;
    }
}