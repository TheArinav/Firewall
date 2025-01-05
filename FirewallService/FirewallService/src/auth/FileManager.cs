using System;
using System.Diagnostics;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using FirewallService.auth.structs;
using Newtonsoft.Json;

namespace FirewallService.auth
{
    public static class FileManager
    {
        public const string DBFile = "/etc/firewall/firewall.db";
        public const string AuthFile = "/etc/firewall/authorized_users.json";
        public const string RSAEncryptionKey = "/etc/firewall/public.key";
        public const int KeySize = 4096;

        public static SecureString RSAKey { get; private set; }
        public static AuthManager AuthManager { get; private set; }

        public static void Init()
        {
            if (!File.Exists(DBFile))
                using (File.Create(DBFile)) { }

            if (!File.Exists(AuthFile))
            {
                using (File.CreateText(AuthFile)) { }

                var emptyAuthObject = new AuthMainObject
                {
                    Users = Array.Empty<UserConnection>()
                };

                var jsonString = JsonConvert.SerializeObject(emptyAuthObject, Formatting.Indented);
                File.WriteAllText(AuthFile, jsonString);
            }

            if (!File.Exists(RSAEncryptionKey))
                File.Delete(RSAEncryptionKey);
            GenerateSecureKey(KeySize);

            SetFilePermissions(DBFile);
            SetFilePermissions(AuthFile);
            SetFilePermissions(RSAEncryptionKey);

            AuthManager = new AuthManager();
        }

        private static void SetFilePermissions(string filePath)
        {
            string cmd = $"chmod 604 {filePath}";

            var escapedArgs = cmd.Replace("\"", "\\\"");
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    FileName = "/bin/bash",
                    Arguments = $"-c \"{escapedArgs}\""
                }
            };

            process.Start();
            process.WaitForExit();

            cmd = $"chown root:root {filePath}";

            escapedArgs = cmd.Replace("\"", "\\\"");
            using var process2 = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    FileName = "/bin/bash",
                    Arguments = $"-c \"{escapedArgs}\""
                }
            };

            process2.Start();
            process2.WaitForExit();
        }

        private static void GenerateSecureKey(int keySize)
        {
            using var rsa = RSA.Create(keySize);
            var privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
            RSAKey = new SecureString();
            foreach (var c in privateKey)
                RSAKey.AppendChar(c);
            RSAKey.MakeReadOnly();
            
            var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
            File.WriteAllText(RSAEncryptionKey, publicKey);
        }

        public static byte[] GetKeyBytes(SecureString secureKey)
        {
            ArgumentNullException.ThrowIfNull(secureKey);

            var bstr = IntPtr.Zero;
            try
            {
                bstr = System.Runtime.InteropServices.Marshal.SecureStringToBSTR(secureKey);
                return Encoding.UTF8.GetBytes(System.Runtime.InteropServices.Marshal.PtrToStringBSTR(bstr));
            }
            finally
            {
                if (bstr != IntPtr.Zero)
                    System.Runtime.InteropServices.Marshal.ZeroFreeBSTR(bstr);
            }
        }
    }
}
