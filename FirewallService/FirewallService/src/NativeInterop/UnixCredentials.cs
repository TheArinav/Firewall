namespace FirewallService.NativeInterop;

using System;
using System.Net.Sockets;
using System.Runtime.InteropServices;

internal static class UnixCredentials
{
    private const int SOL_SOCKET = 1;
    private const int SO_PEERCRED = 17;     // from <linux/socket.h>

    [StructLayout(LayoutKind.Sequential)]
    private struct UCred
    {
        public int pid;   // process ID of the peer
        public int uid;   // user  ID
        public int gid;   // group ID
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int getsockopt(
        int sockfd,
        int level,
        int optname,
        out UCred optval,
        ref int optlen);

    public static int GetPeerPid(Socket socket)
    {
        var len = Marshal.SizeOf<UCred>();
        return getsockopt((int)socket.Handle, SOL_SOCKET, SO_PEERCRED,
            out var cred, ref len) != 0 ? throw new SocketException(Marshal.GetLastWin32Error()) : cred.pid;
    }
}
