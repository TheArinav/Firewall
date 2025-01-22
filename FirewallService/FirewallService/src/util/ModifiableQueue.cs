namespace FirewallService.util;

public class ModifiableQueue<T>
{
    private readonly List<T> _items = new List<T>();

    public void Enqueue(T item) => _items.Add(item);

    public T Dequeue()
    {
        if (_items.Count == 0)
            throw new InvalidOperationException("Queue is empty.");

        var item = _items[0];
        _items.RemoveAt(0); 
        return item;
    }

    public T Peek()
    {
        if (_items.Count == 0)
            throw new InvalidOperationException("Queue is empty.");

        return _items[0];
    }

    public int Count => _items.Count;

    public void ModifyFront(Func<T, T> modify)
    {
        if (_items.Count == 0)
            throw new InvalidOperationException("Queue is empty.");

        _items[0] = modify(_items[0]); 
    }
}

