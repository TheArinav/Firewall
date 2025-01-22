using FirewallService.util;

namespace FirewallService.DB.Entities;

public interface IDataBaseEntity<out T> : IStreamableObject<T>
{
    T Get();
}