using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using FirewallService.auth.structs;
using Newtonsoft.Json;

namespace FirewallService.auth
{
    public static class FileManager
    {
        public const string DBFile = "/etc/firewall/firewall.db";
        public const string AuthFile = "/etc/firewall/authorized_users.json";
        public const string RSAEncryptionKey = "/etc/firewall/public.key";
        private const int KeySize = 4096;
        public static byte[] RSAKey{ get; private set; }
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
            {
                using (File.CreateText(RSAEncryptionKey)) {}

                var keyBytes = GenerateSecureKey(KeySize);
                
                using (StreamWriter writer = new StreamWriter(RSAEncryptionKey))
                {
                    writer.WriteLine(Convert.ToBase64String(keyBytes));
                }
            }
            
            SetFilePermissions(DBFile);
            SetFilePermissions(AuthFile);
            SetFilePermissions(RSAEncryptionKey);

            AuthManager = new AuthManager();
            RSAKey = LoadEncryptionKey(RSAEncryptionKey);
        }
        
        private static void SetFilePermissions(string filePath)
        {
            string cmd = $"chmod 700 {filePath}";

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
        private static byte[] GenerateSecureKey(int keySizeInBits)
        {
            if (keySizeInBits != 128 && keySizeInBits != 192 && keySizeInBits != 256)
                throw new ArgumentException("Key size must be 128, 192, or 256 bits.");

            var keySizeInBytes = keySizeInBits / 8;
            
            var key = new byte[keySizeInBytes];

            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(key);

            return key;
        }
        private static byte[] LoadEncryptionKey(string keyFilePath)
        {
            string base64Key = File.ReadAllText(keyFilePath).Trim();
            
            return Convert.FromBase64String(base64Key);
        }
    }
}
