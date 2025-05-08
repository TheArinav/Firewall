namespace FirewallService.util;

public class Cache<T>(int size, Action<T?>? onRemove = null)
{
    public int Size { get; private set; } = (size > 0) ? size : throw new ArgumentException("Size must be greater than 0.");
    public int Count => _data.Count;
    
    private readonly Dictionary<int, T?> _data = new();
    private readonly ModifiableQueue<int> _dataOrder = new();
    private readonly SortedSet<int> _freeIndices = [];
    private int _nextIndex = 0;
    private Action<T?>? _onRemove = onRemove;

    public void Add(T? item)
    {
        if (Count == Size)
        {
            var removed = _dataOrder.Dequeue();
            _onRemove?.Invoke(_data[removed]);
            _data.Remove(removed);
            _freeIndices.Add(removed);
        }

        int index;
        if (_freeIndices.Count > 0)
        {
            index = _freeIndices.Min;
            _freeIndices.Remove(index);
        }
        else
        {
            index = _nextIndex++;
        }

        _data.Add(index, item);
        _dataOrder.Enqueue(index);
    }

    public T? this[int i]
    {
        get => i >= 0 && i < Count ? _data[_dataOrder[i]] : throw new IndexOutOfRangeException();
        set
        {
            if (i >= 0 && i < Count)
                _data[_dataOrder[i]] = value;
            else
                throw new IndexOutOfRangeException();
        }
    }

    public void RemoveAt(int i)
    {
        var index = _dataOrder[i];
        _data.Remove(index);
        _dataOrder.RemoveAt(i);
        _freeIndices.Add(index);
    }
    
    public bool TryRemove(Func<T, bool> predicate, out T? removed)
    {
        for (var i = 0; i < Count; i++)
        {
            if (!predicate(_data[_dataOrder[i]] ?? throw new InvalidOperationException())) continue;
            removed = _data[_dataOrder[i]];
            RemoveAt(i);
            return true;
        }
        removed = default;
        return false;
    }

}