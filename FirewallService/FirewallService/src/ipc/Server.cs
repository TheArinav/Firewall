using System;
using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using FirewallService.auth;
using FirewallService.DB;
using FirewallService.ipc.structs;

namespace FirewallService.ipc
{
    public class Server : IDisposable
    {
        private readonly AuthManager _authManager;
        private readonly DBManager _dbManager;
        private const int MAX_EVENTS = 10;
        private const string SOCKET_PATH = "/tmp/firewall_uds_epoll_server.sock";
        private readonly ConcurrentQueue<string> _packetQueue;
        public event Action<string> PacketReceived;

        private int _epollFd;
        private Epoll.EpollEvent[]? _events;
        private Socket? _listenerSocket;
        private readonly Dictionary<int, Socket> _clientSockets = new();
        private bool _disposed;

        public Server()
        {
            FileManager.Init();
            _epollFd = -1;
            _packetQueue = new ConcurrentQueue<string>();
            _dbManager = new DBManager();
            _authManager = new AuthManager();
            PacketReceived += ProcessPacket;
        }

        public void Setup()
        {
            _epollFd = Epoll.epoll_create1(0);
            if (_epollFd == -1)
            {
                Console.WriteLine($"Failed to create epoll file descriptor: {Marshal.GetLastWin32Error()}");
                return;
            }

            Console.WriteLine($"epoll_create1 returned FD: {_epollFd}");

            if (File.Exists(SOCKET_PATH))
            {
                File.Delete(SOCKET_PATH);
            }

            _listenerSocket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            _listenerSocket.Bind(new UnixDomainSocketEndPoint(SOCKET_PATH));
            _listenerSocket.Listen(5);
            _listenerSocket.Blocking = false;
            Console.WriteLine($"Listener socket setup complete. FD: {_listenerSocket.Handle}");

            var listenEvent = new Epoll.EpollEvent
            {
                events = Epoll.EPOLLIN | Epoll.EPOLLET,
                data = new Epoll.epoll_data { fd = _listenerSocket.Handle.ToInt32() }
            };

            if (Epoll.epoll_ctl(_epollFd, Epoll.EPOLL_CTL_ADD, _listenerSocket.Handle.ToInt32(), ref listenEvent) == -1)
            {
                Console.WriteLine($"Failed to add listener to epoll: {Marshal.GetLastWin32Error()}");
                return;
            }

            _events = new Epoll.EpollEvent[MAX_EVENTS];
            Console.WriteLine("Server is listening for connections...");
        }

        public void Loop(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                var eventCount = Epoll.epoll_wait(_epollFd, _events!, MAX_EVENTS, 5000);
                if (eventCount == -1)
                {
                    if (Marshal.GetLastWin32Error() == 4) // EINTR
                    {
                        Console.WriteLine("epoll_wait interrupted by signal, stopping...");
                        break;
                    }
                    Console.WriteLine("epoll_wait failed");
                    return;
                }

                for (var i = 0; i < eventCount; i++)
                {
                    var eventFd = _events[i].data.fd;
                    if (eventFd == _listenerSocket?.Handle.ToInt32())
                    {
                        HandleNewConnection();
                    }
                    else if (_clientSockets.TryGetValue(eventFd, out var clientSocket))
                    {
                        HandleClientData(clientSocket);
                    }
                }
            }
        }

        private void HandleNewConnection()
        {
            while (true)
            {
                try
                {
                    var clientSocket = _listenerSocket?.Accept();
                    if (clientSocket == null) break;

                    clientSocket.Blocking = false;
                    var fd = clientSocket.Handle.ToInt32();
                    _clientSockets[fd] = clientSocket;

                    var clientEvent = new Epoll.EpollEvent
                    {
                        events = Epoll.EPOLLIN | Epoll.EPOLLET,
                        data = new Epoll.epoll_data { fd = fd }
                    };

                    if (Epoll.epoll_ctl(_epollFd, Epoll.EPOLL_CTL_ADD, fd, ref clientEvent) == -1)
                    {
                        Console.WriteLine($"Failed to add client to epoll: {Marshal.GetLastWin32Error()}");
                        clientSocket.Close();
                        _clientSockets.Remove(fd);
                    }
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.WouldBlock)
                {
                    break;
                }
            }
        }

        private void HandleClientData(Socket clientSocket)
        {
            var buffer = new byte[4096];
            var fd = clientSocket.Handle.ToInt32();

            try
            {
                int bytesRead = clientSocket.Receive(buffer, SocketFlags.None);
                if (bytesRead > 0)
                {
                    var message = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    _packetQueue.Enqueue(message);
                    PacketReceived?.Invoke(message);
                    clientSocket.Send("Message received!"u8.ToArray());
                }
                else
                {
                    RemoveClient(fd);
                }
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.WouldBlock)
            {
                // No data available
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error handling client {fd}: {ex.Message}");
                RemoveClient(fd);
            }
        }

        private void RemoveClient(int fd)
        {
            if (_clientSockets.TryGetValue(fd, out var socket))
            {
                var ev = new Epoll.EpollEvent();
                Epoll.epoll_ctl(_epollFd, Epoll.EPOLL_CTL_DEL, fd, ref ev);
                socket.Close();
                _clientSockets.Remove(fd);
            }
        }

        private void ProcessPacket(string packet)
        {
            Logger.Debug($"Processing packet: {packet}");
            try
            {
                var message = Message.Parse(packet);
                Logger.Debug($"Parsed message: {message}");
            }
            catch (Exception ex)
            {
                Logger.Error($"Error processing packet: {ex.Message}");
            }
        }

        public void Dispose()
        {
            foreach (var socket in _clientSockets.Values)
            {
                socket.Close();
            }
            _clientSockets.Clear();

            if (_epollFd != -1)
            {
                Epoll.close(_epollFd);
                _epollFd = -1;
            }

            _listenerSocket?.Close();
            if (File.Exists(SOCKET_PATH))
            {
                File.Delete(SOCKET_PATH);
            }
        }
    }
}
