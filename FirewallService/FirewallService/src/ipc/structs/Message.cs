using FirewallService.util;

namespace FirewallService.ipc.structs;

public struct Message : IStreamableObject<Message>
{
    public MessageType Type { get; set; }
    public IMessageComponent<object>? Component { get; set; }
    public long SenderPID { get; set; }
    public long RecepientPID { get; set; }

    public Message()
    {
        this.Type = MessageType.Unset;
        this.Component = null;
        this.SenderPID = -1;
        this.RecepientPID = -1;
    }

    public Message(long sPID, long rPID, IMessageComponent<object>? comp, MessageType type)
    {
        this.SenderPID = sPID;
        this.RecepientPID = rPID;
        this.Component = comp;
        this.Type = type;
    }

    public string ToStringStream()
    {
        return $"{{{SenderPID:X6},{RecepientPID:X6},{SerializeType()},{this.Component?.ToStringStream()}}}";
    }

    private string SerializeType()
    {
        return this.Type switch
        {
            MessageType.Unset    => "0",
            MessageType.Init     => "1",
            MessageType.Request  => "2",
            MessageType.Response => "3",
            _                    => "F"
        };
    }

    private static MessageType DeserializeType(char t)
    {
        return t switch
        {
            '0' => MessageType.Unset,
            '1' => MessageType.Init,
            '2' => MessageType.Request,
            '3' => MessageType.Response,
            _   => throw new ArgumentException("Invalid Input")
        };
    }

    public static Message Parse(string sStream)
    {
        try
        {
            var sPID = long.Parse(sStream.Substring(1, 6));
            var rPID = long.Parse(sStream.Substring(8, 6));
            var mType = DeserializeType(sStream.Substring(15, 1)[0]);

            var componentType = mType switch
            {
                MessageType.Unset    => null,
                MessageType.Init     => typeof(InitRequest),
                MessageType.Request  => typeof(Request),
                MessageType.Response => typeof(Response),
                _                    => null
            };

            var comp = (IMessageComponent<object>)componentType?
                .GetMethod( "Parse",
                    System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.Public)?
                .Invoke(null, [EncryptionManager.DecryptMessageComponent(sPID,mType,sStream[17..^1])])!;
            
            return new Message(sPID, rPID, comp, mType);
        }
        catch (Exception e)
        {
            if (e is FormatException)
                throw;
            throw new FormatException($"Invalid Message. Error thrown = {e.GetType()}:{e.Message}");
        }
    }
}