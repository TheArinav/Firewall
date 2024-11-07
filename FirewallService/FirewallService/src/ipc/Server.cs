using System;
using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Text;
using FirewallService.auth;
using FirewallService.DB;
using FirewallService.ipc.structs;
using static FirewallService.ipc.Epoll;

namespace FirewallService.ipc
{
    public class Server
    {
        private readonly AuthManager _authManager;
        private readonly DBManager _dbManager;
        private const int MAX_EVENTS = 10;
        private const string SOCKET_PATH = "/tmp/firewall_uds_epoll_server.sock";

        /// <summary>
        /// Thread-safe queue to store incoming packets
        /// </summary>
        private readonly ConcurrentQueue<string> _packetQueue;

        /// <summary>
        /// Event that is triggered when a packet is enqueued
        /// </summary>
        public event Action<string> PacketReceived;

        private int _epollFd;
        private EpollEvent[]? _events;
        private Socket? _listenerSocket;

        public Server()
        {
            _epollFd = default;
            this._events = default;
            this._listenerSocket = default;
            this._packetQueue = new ConcurrentQueue<string>();
            this._dbManager = new DBManager();
            this._authManager = new AuthManager();
            this.PacketReceived += ProcessPacket;
        }

        public void Setup()
        {
            this._epollFd = epoll_create1(0);
            if (this._epollFd == -1)
            {
                Console.WriteLine("Failed to create epoll file descriptor");
                return;
            }
            
            this._listenerSocket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            if (File.Exists(SOCKET_PATH))
                File.Delete(SOCKET_PATH);
            
            this._listenerSocket.Bind(new UnixDomainSocketEndPoint(SOCKET_PATH));
            this._listenerSocket.Listen(5);
            
            var listenEvent = new EpollEvent
            {
                events = EPOLLIN | EPOLLET, 
                fd = this._listenerSocket.Handle.ToInt32()
            };
            
            if (epoll_ctl(this._epollFd, EPOLL_CTL_ADD, listenEvent.fd, ref listenEvent) == -1)
            {
                Console.WriteLine("Failed to add listener socket to epoll");
                return ;
            }

            Console.WriteLine("Server is listening for connections...");
            
             this._events = new EpollEvent[MAX_EVENTS];
            
        }

        public void Loop()
        {
            var eventCount = epoll_wait(_epollFd, _events, MAX_EVENTS, -1);
            if (eventCount == -1)
            {
                Console.WriteLine("epoll_wait failed");
                return;
            }

            for (var i = 0; i < eventCount; i++)
            {
                if (_events?[i].fd == _listenerSocket?.Handle.ToInt32())
                {
                    var clientSocket = _listenerSocket?.Accept();
                    Console.WriteLine("New client connected.");

                    if (clientSocket == null) continue;
                    clientSocket.Blocking = false;

                    var clientEvent = new EpollEvent
                    {
                        events = EPOLLIN | EPOLLET,
                        fd = clientSocket.Handle.ToInt32()
                    };

                    if (epoll_ctl(_epollFd, EPOLL_CTL_ADD, clientEvent.fd, ref clientEvent) == -1)
                        Console.WriteLine("Failed to add client socket to epoll");
                }
                else
                {
                    if (_events == null) continue;
                    var clientFd = _events[i].fd;
                    var clientSocket = new Socket(new SafeSocketHandle(new IntPtr(clientFd), ownsHandle: true));
                    HandleClientData(clientSocket);
                }
            }
        }

        private void HandleClientData(Socket clientSocket)
        {
            var buffer = new byte[1024];
            try
            {
                var bytesRead = clientSocket.Receive(buffer);
                if (bytesRead > 0)
                {
                    var message = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                    _packetQueue.Enqueue(message);
                    
                    PacketReceived?.Invoke(message);

                    var response = Encoding.UTF8.GetBytes("Message received!");
                    clientSocket.Send(response);
                }
                else
                {
                    Console.WriteLine("Client disconnected");
                    clientSocket.Close();
                }
            }
            catch (SocketException ex)
            {
                Console.WriteLine($"Socket error: {ex.Message}");
            }
        }

        private void ProcessPacket(string packet)
        {
            var req = Request.Parse(packet);
            var resp = new Response();
            if (!this._authManager.Validate(req.Requester, req.SQLQuery, out var authResp))
            {
                resp.OperationSuccessful = false;
                resp.Message = authResp;
            }
            else
                resp = this._dbManager.HandleRequest(req);
        }
        ~Server()
        {
            close(_epollFd);
            _listenerSocket?.Close();
        }
    }
}

