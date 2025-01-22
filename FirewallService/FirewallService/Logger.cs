using System.ComponentModel;
using System.Runtime.CompilerServices;
using FirewallService.util;
using Microsoft.Extensions.Logging;

namespace FirewallService
{
    enum LogType
    {
        Regular,
        Read,
        Warning,
        Error,
        Critical,
        Info,
        Debug
    }
    
    public static class Logger
    {
        private static ILogger? _logger;
        private static ModifiableQueue<(ulong lockID, int life)> _lockQueue = new();
        private static Dictionary<ulong, Queue<(LogType type, string cont)>> _awaiting = new();
        private static Dictionary<ulong, Queue<string>> _inputOut = new();
        private static Dictionary<ulong, AutoResetEvent> _readSignalProvider = new();
        private const int MAX_LIFE = 10;
        private static readonly object mutex = new();
        private static readonly BackgroundWorker _worker = new();
        
        public static void Initialize(ILogger logger)
        {
            _logger = logger;
            
            // Initialize the default queue (k=0)
            _awaiting[0] = new Queue<(LogType type, string cont)>();
            _inputOut[0] = new Queue<string>();
            _readSignalProvider[0] = new AutoResetEvent(false);
            
            _worker.DoWork += (o, e) =>
            {
                while (!_worker.CancellationPending)
                {
                    bool fpublic;
                    (ulong lockID, int life)? _lock = null;
                    
                    lock (mutex)
                    {
                        fpublic = _lockQueue.Count == 0;
                        if (!fpublic)
                            _lock = _lockQueue.Peek();
                    }

                    // Process messages for both public (0) and locked queues
                    var id = fpublic ? 0UL : _lock.Value.lockID;
                    
                    lock (mutex)
                    {
                        if (_awaiting.ContainsKey(id) && _awaiting[id].Count > 0)
                        {
                            var (type, msg) = _awaiting[id].Dequeue();
                            if (msg != null)
                            {
                                // Release lock before logging to prevent deadlocks
                                Monitor.Exit(mutex);
                                try
                                {
                                    DoLog(msg, type, id);
                                }
                                finally
                                {
                                    Monitor.Enter(mutex);
                                }
                            }
                        }
                    }

                    if (!fpublic)
                    {
                        lock (mutex)
                        {
                            if (_lock.Value.life - 1 == 0)
                                _lockQueue.Dequeue();
                            else
                                _lockQueue.ModifyFront(tuple => (tuple.lockID, tuple.life - 1));
                        }
                    }

                    // Add a small delay to prevent CPU spinning
                    Thread.Sleep(1);
                }
            };
            
            // Start the worker
            _worker.RunWorkerAsync();
        }

        private static void DoLog(string msg, LogType type, ulong id)
        {
            if (string.IsNullOrEmpty(msg))
                throw new ArgumentNullException(nameof(msg));
                
            switch (type)
            {
                case LogType.Regular:
                    Console.WriteLine(msg);
                    break;
                case LogType.Read:
                    Console.Write(msg);
                    var inp = Console.ReadLine();
                    lock (mutex)
                    {
                        _inputOut[id].Enqueue(inp ?? string.Empty);
                    }
                    _readSignalProvider[id].Set();
                    break;
                case LogType.Warning:
                    _logger?.LogWarning(msg);
                    break;
                case LogType.Error:
                    _logger?.LogError(msg);
                    break;
                case LogType.Critical:
                    _logger?.LogCritical(msg);
                    break;
                case LogType.Info:
                    _logger?.LogInformation(msg);
                    break;
                case LogType.Debug:
                    _logger?.LogDebug(msg);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }

        public static void CreateLock(ulong key, int lifetime)
        {
            if (lifetime is < 1 or > MAX_LIFE)
                throw new ArgumentOutOfRangeException($"A lock lifetime must be between 1 and {MAX_LIFE}", nameof(lifetime));
            if (key == 0)
                throw new ArgumentException("A lock can't be created on the public ID", nameof(key));
                
            lock (mutex)
            {
                _lockQueue.Enqueue((key, lifetime));
                if (!_awaiting.ContainsKey(key))
                    _awaiting[key] = new Queue<(LogType type, string cont)>();
                if (!_inputOut.ContainsKey(key))
                    _inputOut[key] = new Queue<string>();
                if (!_readSignalProvider.ContainsKey(key))
                    _readSignalProvider[key] = new AutoResetEvent(false);
            }
        }

        private static void ForwardRequest(LogType type, string msg, ulong k)
        {
            if (string.IsNullOrEmpty(msg))
                return;
                
            lock (mutex)
            {
                if (!_awaiting.ContainsKey(k))
                {
                    if (k == 0)
                    {
                        _awaiting[k] = new Queue<(LogType type, string cont)>();
                    }
                    else
                    {
                        return;
                    }
                }
                _awaiting[k].Enqueue((type, msg));
            }
        }

        public static void Info(string message, ulong k = 0)
        {
            ForwardRequest(LogType.Info, message, k);
        }

        public static void Error(string message, ulong k = 0)
        {
            ForwardRequest(LogType.Error, message, k);
        }

        public static void Debug(string message, ulong k = 0)
        {
            ForwardRequest(LogType.Debug, message, k);
        }

        public static void Warn(string message, ulong k = 0)
        {
            ForwardRequest(LogType.Warning, message, k);
        }

        public static void Critical(string message, ulong k = 0)
        {
            ForwardRequest(LogType.Critical, message, k);
        }

        public static void RegWrite(string message, ulong k = 0)
        {
            ForwardRequest(LogType.Regular, message, k);
        }
        
        public static string Read(string message, ulong k = 0)
        {
            ForwardRequest(LogType.Read, message, k);
            _readSignalProvider[k].WaitOne();
            lock (mutex)
            {
                return _inputOut[k].Dequeue();
            }
        }
    }
}
