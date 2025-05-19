using FirewallService.util;

namespace FirewallService.DB.util;

public interface IDataBaseEntity<out T> : IStreamableObject<T>
{
    T Get();
}