using FirewallService.util;

namespace FirewallService.ipc.structs;

public interface IMessageComponent<out T> : IStreamableObject<T>
{
    
}