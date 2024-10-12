namespace FirewallService.ipc.structs;

public struct Message
{
    public MessageType Type;
    public IMessageComponent Component;
    public long SenderPID;
    public long RecepientPID;

    public Message()
    {
        this.Type = MessageType.Unset;
        this.Component = null;
        this.SenderPID = -1;
        this.RecepientPID = -1;
    }
}