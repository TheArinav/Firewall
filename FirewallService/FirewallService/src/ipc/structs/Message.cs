using FirewallService.util;

namespace FirewallService.ipc.structs;

public struct Message : IStreamableObject<Message>
{
    public MessageType Type;
    public IMessageComponent<object>? Component;
    public long SenderPID;
    public long RecepientPID;

    public Message()
    {
        this.Type = MessageType.Unset;
        this.Component = null;
        this.SenderPID = -1;
        this.RecepientPID = -1;
    }

    public Message(long sPID, long rPID, IMessageComponent<object>? comp)
    {
        this.SenderPID = sPID;
        this.RecepientPID = rPID;
        this.Component = comp;
    }

    public string ToStringStream()
    {
        return $"{{{SenderPID:X6},{RecepientPID:X6},{this.Component?.ToStringStream()}}}";
    }

    public static Message Parse(string sStream, Type? componentType)
    {
        var comp = (IMessageComponent<object>)componentType?
            .GetMethod("Parse",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.Public)?
            .Invoke(null, [sStream])!;
        var sPID = long.Parse(sStream.Substring(1, 6));
        var rPID = long.Parse(sStream.Substring(8, 6));
        return new Message(sPID,rPID,comp);
    }
}