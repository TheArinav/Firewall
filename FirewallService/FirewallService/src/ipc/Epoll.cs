using System.Runtime.InteropServices;

namespace FirewallService.ipc;


public static class Epoll
{
    public const uint EPOLLIN = 0x001;
    public const uint EPOLLOUT = 0x004;
    public const uint EPOLLERR = 0x008;
    public const uint EPOLLET = 0x80000000;
    public const int EPOLL_CTL_ADD = 1;
    public const int EPOLL_CTL_DEL = 2;
    public const int EPOLL_CTL_MOD = 3;

    [StructLayout(LayoutKind.Explicit)]
    public struct epoll_data
    {
        [FieldOffset(0)]
        public IntPtr ptr;
        [FieldOffset(0)]
        public int fd;
        [FieldOffset(0)]
        public uint u32;
        [FieldOffset(0)]
        public ulong u64;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EpollEvent
    {
        public uint events;
        public epoll_data data;
    }

    [DllImport("libc", SetLastError = true)]
    public static extern int epoll_create1(int flags);

    [DllImport("libc", SetLastError = true)]
    public static extern int epoll_ctl(int epfd, int op, int fd, ref EpollEvent _event);

    [DllImport("libc", SetLastError = true)]
    public static extern int epoll_wait(int epfd, [Out] EpollEvent[] events, int maxevents, int timeout);

    [DllImport("libc", SetLastError = true)]
    public static extern int close(int fd);
}
