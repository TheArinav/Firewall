using System;
using System.Runtime.InteropServices;

namespace FirewallService.NativeInterop
{
    public static class UnixNative
    {
        [DllImport("libc", SetLastError = true)]
        public static extern int chmod(string path, int mode);

        [Flags]
        public enum FilePermissions
        {
            S_IRWXU = 0x1C0, // Read, write, execute by owner
            S_IRUSR = 0x100, // Read by owner
            S_IWUSR = 0x080, // Write by owner
            S_IXUSR = 0x040, // Execute by owner
            S_IRWXG = 0x038, // Read, write, execute by group
            S_IRGRP = 0x020, // Read by group
            S_IWGRP = 0x010, // Write by group
            S_IXGRP = 0x008, // Execute by group
            S_IRWXO = 0x007, // Read, write, execute by others
            S_IROTH = 0x004, // Read by others
            S_IWOTH = 0x002, // Write by others
            S_IXOTH = 0x001  // Execute by others
        }
    }
}
