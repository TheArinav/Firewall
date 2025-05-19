using System;
using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using FirewallService.managers;
using FirewallService.managers.structs;
using FirewallService.DB;
using FirewallService.DB.Entities;
using FirewallService.DB.util;
using FirewallService.ipc.structs;
using FirewallService.ipc.structs.GeneralActionStructs;
using FirewallService.NativeInterop;
using FirewallService.util;
using Microsoft.VisualBasic;
using static FirewallService.ipc.Epoll;
using static FirewallService.NativeInterop.UnixNative;

namespace FirewallService.ipc
{
    public enum SessionState
    {
        Uninitialized,
        Idle,
        Active
    }
    public class Session(SessionState state, EpollEvent? @event, Socket socket)
    {
        public SessionState State = state;
        public EpollEvent? Event = @event;
        public Socket Socket = socket;
    }

    public class Server : IDisposable
    {
        
        private const int MAX_ACTIVE = 128;
        private const int MAX_IDLE = 64;
        private const int MAX_EVENTS = MAX_ACTIVE + MAX_IDLE;
        private readonly EpollEvent[] _events = new EpollEvent[MAX_EVENTS];
        private const string SOCKET_PATH = "/run/firewall_uds_epoll_server.sock";
        private readonly ConcurrentQueue<string> _packetQueue;
        
        public delegate void OnPacketReceived<T1,T2,T3,T4>(T1 a, T4 f, out T1 b, out T2 c, out T3 d, out T2 e);
        public event OnPacketReceived<string,bool,long,int> PacketReceived;

        private int _epollFd;
        private Cache<Session?> _idleSessions;
        private Dictionary<int, Session> _activeSessions = new();

        private Socket? _listenerSocket;
        private readonly Dictionary<int, Socket> _clientSockets = new();
        private readonly Dictionary<int, long> _fdToClientIdMap = new();
        private bool _disposed;
        
        private readonly ConcurrentDictionary<string, long> _usedNonces = new(); // Nonce → Timestamp
        private const int TIMESTAMP_TOLERANCE = 30; // Allow timestamps up to 30 seconds old
        
        private bool _ceWarningProvided = false;
        
        public Server()
        {
            GeneralManager.Init();
            _epollFd = -1;
            _packetQueue = new ConcurrentQueue<string>();
            GeneralManager.ActionManager = new ActionManager();
            PacketReceived += ProcessPacket;
            Setup();
        }

        private void Setup()
        {
            _epollFd = epoll_create1(0);
            if (_epollFd == -1)
            {
                Logger.Error($"Failed to create epoll file descriptor: {Marshal.GetLastWin32Error()}");
                return;
            }

            Logger.Info($"epoll_create1 returned FD: {_epollFd}");

            if (File.Exists(SOCKET_PATH))
                File.Delete(SOCKET_PATH);
            

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

            var listenEvent = new EpollEvent
            {
                events = EPOLLIN | EPOLLET,
                data = new epoll_data { fd = _listenerSocket.Handle.ToInt32() }
            };

            if (epoll_ctl(_epollFd, EPOLL_CTL_ADD, _listenerSocket.Handle.ToInt32(), ref listenEvent) == -1)
            {
                Logger.Error($"Failed to add listener to epoll: {Marshal.GetLastWin32Error()}");
                return;
            }

            _idleSessions = new Cache<Session?>(64, session =>
            {
                try
                {
                    session?.Socket.Shutdown(SocketShutdown.Both);
                }
                catch
                {
                    // ignored
                }

                session?.Socket.Close();
                if (_ceWarningProvided) return;
                Logger.Warn("Idle session cache eviction, too many inactive sessions. Is the server being attacked?");
                _ceWarningProvided = true;
            });

            Logger.Info("Server is listening for connections...");
        }

        public void Loop(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                var eventCount = epoll_wait(_epollFd, _events!, MAX_EVENTS, 5000);
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
                        HandleNewConnection();
                    else if (_clientSockets.TryGetValue(eventFd, out var clientSocket))
                        HandleClientData(clientSocket);
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

                    var clientEvent = new EpollEvent
                    {
                        events = EPOLLIN | EPOLLET,
                        data = new epoll_data { fd = fd }
                    };

                    if (epoll_ctl(_epollFd, EPOLL_CTL_ADD, fd, ref clientEvent) == -1)
                    {
                        Logger.Error($"Failed to add client to epoll: {Marshal.GetLastWin32Error()}");
                        clientSocket.Close();
                        _clientSockets.Remove(fd);
                        return;
                    }

                    var session = new Session(SessionState.Idle, clientEvent, clientSocket);
                    _idleSessions.Add(session);
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
                var peerPID = UnixCredentials.GetPeerPid(clientSocket);
                if (bytesRead > 0)
                {
                    

                    var message = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    _packetQueue.Enqueue(message);
                    string? resp = null;
                    var fin = false;
                    var id = 0L;
                    var promote = false;
                    PacketReceived?.Invoke(message,peerPID, out resp, out fin, out id, out promote);
                    if (promote)
                    {
                        // Promote session from idle to active if not already active
                        if (!_activeSessions.ContainsKey(fd))
                        {
                            if (_idleSessions.TryRemove(s => s.Socket.Handle.ToInt32() == fd, out var session))
                            {
                                session.State = SessionState.Active;
                                _activeSessions[fd] = session;
                            }
                        }
                    }
                    var defaultResp = new Response(false,"Error processing packet", null,
                        EncryptionManager.SecureStringToByteArray(EncryptionManager.SessionKeys[peerPID]));
                    var def = (new Message(Environment.ProcessId, peerPID, defaultResp, MessageType.Response)).ToStringStream();
                    clientSocket.Send(Encoding.UTF8.GetBytes(resp ?? def));
                    _fdToClientIdMap[fd] = id;

                    if (!fin) return;

                    clientSocket.Shutdown(SocketShutdown.Both);
                    clientSocket.Close();
                }
                else
                {
                    if (_fdToClientIdMap.TryGetValue(fd, out var id))
                    {
                        GeneralManager.AuthManager.MainObject?.Disconnect(id);
                        _fdToClientIdMap.Remove(fd);
                    }
                }

                RemoveClient(fd);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.WouldBlock)
            {
                // No data
            }
            catch (Exception ex)
            {
                Logger.Error($"Error handling client {fd}: {ex.Message}");
                RemoveClient(fd);
            }
        }


        private void RemoveClient(int fd)
        {
            if (_activeSessions.Remove(fd, out var activeSession))
                activeSession.Socket.Close();
            else if (_idleSessions.TryRemove(s => s.Socket.Handle.ToInt32() == fd, out _))
            {
                // Already closed via cache eviction
            }

            var ev = new EpollEvent();
            epoll_ctl(_epollFd, EPOLL_CTL_DEL, fd, ref ev);
            _clientSockets.Remove(fd);
        }

        private void ProcessPacket(string packet,int pid, out string mes, out bool fin, out long userId, out bool promote)
        {
            mes = null;
            fin = true;
            userId = -1; 
            long reqID = -1;
            promote = false;
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

                if (message.SenderPID != pid)
                {
                    Logger.Warn("Received a packet with incorrect sender PID.");
                    return;
                }

                switch (message.Type)
                {
                    case MessageType.InitSessionRequest:
                    {
                        var usr = ((message.Component as InitSessionRequest)!).Requester;
                        reqID = usr.ID;
                        var k = ((message.Component as InitSessionRequest)!).AESKey;
                        var conn = GeneralManager.AuthManager.Validate(usr, "login",
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
                        promote = conn;
                        if (promote)
                            EncryptionManager.SessionKeys.Add(message.SenderPID, BytesToSecureString(k));
                    }  break;
                    case MessageType.Response:
                        break;
                    case MessageType.GeneralActionRequest:
                    {
                        var usr = (message.Component as GeneralActionRequest)!.Requester;
                        reqID = usr.ID;
                        var rspBody = "";
                        Response? rsp = null;
                        var user = GeneralManager.AuthManager.MainObject?.GetUser(reqID) ?? new AuthorizedUser(-1,"");
                        if (user.ID == -1)
                        {
                            rspBody = "Failed to authenticate user session.";
                            goto end;
                        }
                        var flag = GeneralManager.AuthManager.Validate(user,
                            ((message.Component as GeneralActionRequest)!).RequestBody,
                            out var outMes, out _);
                        if (!flag)
                        {
                            rspBody = "Action is not permitted.";
                            goto end;
                        }

                        rsp = GeneralManager.ActionManager.Execute((message.Component as GeneralActionRequest)!);
                        
                        end:
                        {
                            usr.Token.Open();
                            rsp ??= new Response(false,rspBody,null,usr.Token.GetBytes());
                            var resp = (Response)rsp;
                            resp.Key = EncryptionManager.SecureStringToByteArray(EncryptionManager.SessionKeys[message.SenderPID]);
                            var oMes = new Message(
                                Environment.ProcessId,
                                message.SenderPID,
                                resp.Get(),
                                MessageType.Response);
                            mes = oMes.ToStringStream();
                            fin = false;
                        }
                    }
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
                GeneralManager.AuthManager.MainObject?.Disconnect(reqID);
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
                close(_epollFd);
                _epollFd = -1;
            }

            _listenerSocket?.Close();
            if (File.Exists(SOCKET_PATH))
            {
                File.Delete(SOCKET_PATH);
            }
        }
        private static SecureString BytesToSecureString(byte[] bytes, Encoding encoding = null)
        {
            ArgumentNullException.ThrowIfNull(bytes);

            var secure = new SecureString();
            foreach (var b in bytes)
                secure.AppendChar((char)b); // Store byte directly as char

            secure.MakeReadOnly();
            return secure;
        }
    }
}
