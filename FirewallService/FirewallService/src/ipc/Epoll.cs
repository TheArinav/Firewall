using System.Runtime.InteropServices;

namespace FirewallService.ipc;

public static class Epoll
{
    // epoll flags
    public const uint EPOLLIN = 0x001;
    public const uint EPOLLOUT = 0x004;
    public const uint EPOLLERR = 0x008;
    public const uint EPOLLET = 0x80000000; // Edge-triggered behavior
    public const int EPOLL_CTL_ADD = 1;    // Add file descriptor to epoll
    public const int EPOLL_CTL_DEL = 2;    // Remove file descriptor from epoll
    public const int EPOLL_CTL_MOD = 3;    // Modify file descriptor in epoll

    [StructLayout(LayoutKind.Sequential)]
    public struct EpollEvent
    {
        public uint events;  // Epoll events
        public int fd;       // File descriptor
    }

    // Import native epoll functions from libc
    [DllImport("libc", SetLastError = true)]
    public static extern int epoll_create1(int flags);

    [DllImport("libc", SetLastError = true)]
    public static extern int epoll_ctl(int epfd, int op, int fd, ref EpollEvent _event);

    [DllImport("libc", SetLastError = true)]
    public static extern int epoll_wait(int epfd, EpollEvent[]? events, int maxevents, int timeout);

    [DllImport("libc", SetLastError = true)]
    public static extern int close(int fd);
}