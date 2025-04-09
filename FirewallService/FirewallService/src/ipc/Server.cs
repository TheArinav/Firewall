using System;
using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using FirewallService.auth;
using FirewallService.DB;
using FirewallService.ipc.structs;
using static FirewallService.NativeInterop.UnixNative;

namespace FirewallService.ipc
{
    public class Server : IDisposable
    {
        private readonly AuthManager _authManager;
        private readonly DBManager _dbManager;
        private const int MAX_EVENTS = 10;
        private const string SOCKET_PATH = "/run/firewall_uds_epoll_server.sock";
        private readonly ConcurrentQueue<string> _packetQueue;
        

        public delegate void OnPacketReceived<T1,T2,T3>(T1 a, out T1 b, out T2 c, out T3 d);
        public event OnPacketReceived<string,bool,long> PacketReceived;

        private int _epollFd;
        private Epoll.EpollEvent[]? _events;
        private Socket? _listenerSocket;
        private readonly Dictionary<int, Socket> _clientSockets = new();
        private readonly Dictionary<int, long> _fdToClientIdMap = new();
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
                Logger.Error($"Failed to create epoll file descriptor: {Marshal.GetLastWin32Error()}");
                return;
            }

            Logger.Info($"epoll_create1 returned FD: {_epollFd}");

            if (File.Exists(SOCKET_PATH))
            {
                File.Delete(SOCKET_PATH);
            }

            _listenerSocket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            _listenerSocket.Bind(new UnixDomainSocketEndPoint(SOCKET_PATH));
            _listenerSocket.Listen(5);
            _listenerSocket.Blocking = false;
            Logger.Info($"Listener socket setup complete. FD: {_listenerSocket.Handle}");

            try
            {
                // Allow read/write access to all users
                File.SetAttributes(SOCKET_PATH, FileAttributes.Normal);
                _ = chmod(SOCKET_PATH,
                    (int)(FilePermissions.S_IRUSR | FilePermissions.S_IWUSR | 
                               FilePermissions.S_IRGRP | FilePermissions.S_IWGRP |
                               FilePermissions.S_IROTH | FilePermissions.S_IWOTH));
                Logger.Info("Socket file permissions updated to allow all users access.");
            }
            catch (Exception ex)
            {
                Logger.Error($"Failed to update socket file permissions: {ex.Message}");
            }

            var listenEvent = new Epoll.EpollEvent
            {
                events = Epoll.EPOLLIN | Epoll.EPOLLET,
                data = new Epoll.epoll_data { fd = _listenerSocket.Handle.ToInt32() }
            };

            if (Epoll.epoll_ctl(_epollFd, Epoll.EPOLL_CTL_ADD, _listenerSocket.Handle.ToInt32(), ref listenEvent) == -1)
            {
                Logger.Error($"Failed to add listener to epoll: {Marshal.GetLastWin32Error()}");
                return;
            }

            _events = new Epoll.EpollEvent[MAX_EVENTS];
            Logger.Info("Server is listening for connections...");
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
                        Logger.Info("epoll_wait interrupted by signal, stopping...");
                        break;
                    }
                    Logger.Error("epoll_wait failed");
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

                    if (Epoll.epoll_ctl(_epollFd, Epoll.EPOLL_CTL_ADD, fd, ref clientEvent) != -1) continue;
                    
                    Logger.Error($"Failed to add client to epoll: {Marshal.GetLastWin32Error()}");
                    clientSocket.Close();
                    _clientSockets.Remove(fd);
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
                var bytesRead = clientSocket.Receive(buffer, SocketFlags.None);
                if (bytesRead > 0)
                {
                    var message = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    _packetQueue.Enqueue(message);
                    string? resp  = null;
                    var fin = false;
                    var id = 0L;
                    PacketReceived?.Invoke(message, out resp, out fin, out id);
                    clientSocket.Send(Encoding.UTF8.GetBytes(resp?? "Error processing packet"));
                    _fdToClientIdMap.Add(fd,id);
                    if (!fin) return;
                    clientSocket.Shutdown(SocketShutdown.Both);
                    clientSocket.Close();
                }
                else
                {
                    if (_fdToClientIdMap.TryGetValue(fd, out var id))
                    {
                        _authManager.MainObject?.Disconnect(id);
                        _fdToClientIdMap.Remove(fd);
                    }
                }
                RemoveClient(fd);
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
            if (!_clientSockets.TryGetValue(fd, out var socket)) return;
            var ev = new Epoll.EpollEvent();
            Epoll.epoll_ctl(_epollFd, Epoll.EPOLL_CTL_DEL, fd, ref ev);
            socket.Close();
            _clientSockets.Remove(fd);
        }

        private readonly ConcurrentDictionary<string, long> _usedNonces = new(); // Nonce → Timestamp
        private const int TIMESTAMP_TOLERANCE = 30; // Allow timestamps up to 30 seconds old

        private void ProcessPacket(string packet, out string mes, out bool fin, out long userId)
        {
            mes = null;
            fin = true;
            userId = -1; 
            long reqID = -1;
            Logger.Info($"Processing packet: {packet}");
            try
            {
                var message = Message.Parse(packet);

                var currentTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                if (message.Timestamp < currentTimestamp - TIMESTAMP_TOLERANCE)
                {
                    Logger.Warn("Received a packet with an expired timestamp.");
                    return;
                }

                if (_usedNonces.ContainsKey(message.Nonce))
                {
                    Logger.Warn("Received a duplicate packet (replay detected).");
                    return;
                }

                _usedNonces.TryAdd(message.Nonce, message.Timestamp);

                switch (message.Type)
                {
                    case MessageType.InitSessionRequest:
                        var usr = ((message.Component as InitSessionRequest)!).Requester;
                        reqID = usr.ID;
                        var k = ((message.Component as InitSessionRequest)!).AESKey;
                        var conn = _authManager.Validate(usr, "login",
                            out var mess, out var connection, args: [k]);
                        var responseBody = $"{mess}|{connection?.User.Token.ToString() ?? "null"}";
                        var resp = new Response(conn, responseBody, null, k);
                        var oMes = new Message(
                            Environment.ProcessId,
                            message.SenderPID,
                            resp.Get(),
                            MessageType.Response
                        );
                        mes = oMes.ToStringStream();
                        fin = !conn;
                        break;
                    case MessageType.Response:
                        break;
                    case MessageType.GeneralActionRequest:
                        break;
                    default:
                        throw new ArgumentOutOfRangeException();
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Error processing packet: {ex.Message}");
            }
            finally
            {
                if (!fin || reqID == -1) goto end;
                _authManager.MainObject.Disconnect(reqID);
                end:
                if (reqID != -1)
                    userId = reqID;
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
