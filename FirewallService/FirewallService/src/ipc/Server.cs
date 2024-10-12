using System;
using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Text;
using System.IO;
using System.Threading.Tasks;
using static FirewallService.ipc.Epoll;

namespace FirewallService.ipc
{
    public class Server
    {
        private const int MaxEvents = 10;
        private const string SocketPath = "/tmp/firewall_uds_epoll_server.sock";

        /// <summary>
        /// Thread-safe queue to store incoming packets
        /// </summary>
        private readonly ConcurrentQueue<string> PacketQueue;

        /// <summary>
        /// Event that is triggered when a packet is enqueued
        /// </summary>
        public event Action<string> PacketReceived;

        public Server()
        {
            this.PacketQueue = new ConcurrentQueue<string>();
            this.PacketReceived += ProcessPacket;
        }

        public void Start()
        {
            var epollFd = epoll_create1(0);
            if (epollFd == -1)
            {
                Console.WriteLine("Failed to create epoll file descriptor");
                return;
            }
            
            var listenerSocket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            if (File.Exists(SocketPath))
                File.Delete(SocketPath);
            
            listenerSocket.Bind(new UnixDomainSocketEndPoint(SocketPath));
            listenerSocket.Listen(5);
            
            var listenEvent = new EpollEvent
            {
                events = EPOLLIN | EPOLLET, 
                fd = listenerSocket.Handle.ToInt32()
            };
            
            if (epoll_ctl(epollFd, EPOLL_CTL_ADD, listenEvent.fd, ref listenEvent) == -1)
            {
                Console.WriteLine("Failed to add listener socket to epoll");
                return;
            }

            Console.WriteLine("Server is listening for connections...");
            
            var events = new EpollEvent[MaxEvents];

            while (true)
            {
                var eventCount = epoll_wait(epollFd, events, MaxEvents, -1);
                if (eventCount == -1)
                {
                    Console.WriteLine("epoll_wait failed");
                    break;
                }

                for (var i = 0; i < eventCount; i++)
                {
                    if (events[i].fd == listenerSocket.Handle.ToInt32())
                    {
                        var clientSocket = listenerSocket.Accept();
                        Console.WriteLine("New client connected.");
                        
                        clientSocket.Blocking = false;
                        
                        var clientEvent = new EpollEvent
                        {
                            events = EPOLLIN | EPOLLET,
                            fd = clientSocket.Handle.ToInt32()
                        };

                        if (epoll_ctl(epollFd, EPOLL_CTL_ADD, clientEvent.fd, ref clientEvent) == -1)
                            Console.WriteLine("Failed to add client socket to epoll");
                    }
                    else
                    {
                        var clientFd = events[i].fd;
                        var clientSocket = new Socket(new SafeSocketHandle(new IntPtr(clientFd), ownsHandle: true));
                        HandleClientData(clientSocket);
                    }
                }
            }
            close(epollFd);
            listenerSocket.Close();
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

                    PacketQueue.Enqueue(message);
                    
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
            
        }
    }
}
