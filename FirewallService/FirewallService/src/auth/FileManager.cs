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
        public const string RSAPrivateKey = "/etc/firewall/private.key";  // Store private key securely
        public const int KeySize = 4096;

        public static SecureString RSAKey { get; private set; }
        public static AuthManager AuthManager { get; private set; }

        public static void Init()
        {
            if (!File.Exists(DBFile))
                using (File.Create(DBFile))
                {
                }

            if (!File.Exists(AuthFile))
            {
                Logger.Warn("Detected empty authentication file; No login allowed.");
                using (File.CreateText(AuthFile))
                {
                }

                var emptyAuthObject = new AuthMainObject
                {
                    Users = []
                };

                var jsonString = JsonConvert.SerializeObject(emptyAuthObject, Formatting.Indented);
                File.WriteAllText(AuthFile, jsonString);
            }

            if (!File.Exists(RSAEncryptionKey) || !File.Exists(RSAPrivateKey))
                GenerateSecureKey(KeySize);

            SetFilePermissions(DBFile, "600");
            SetFilePermissions(AuthFile, "600");
            SetFilePermissions(RSAEncryptionKey, "644");
            SetFilePermissions(RSAPrivateKey, "600");

            AuthManager = new AuthManager();
        }

        private static void SetFilePermissions(string filePath, string permissions)
        {
            string cmd = $"chmod {permissions} {filePath} && chown root:root {filePath}";

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
        }

        private static void GenerateSecureKey(int keySize)
        {
            using var rsa = RSA.Create(keySize);
            rsa.KeySize = keySize;

            // Export and store the private key securely
            var privateKeyBytes = rsa.ExportPkcs8PrivateKey();
            string privateKeyPEM = ConvertToPem(privateKeyBytes, "PRIVATE KEY");
            File.WriteAllText(RSAPrivateKey, privateKeyPEM);

            // Store in SecureString for additional security
            RSAKey = new SecureString();
            foreach (char c in privateKeyPEM)
            {
                RSAKey.AppendChar(c);
            }
            RSAKey.MakeReadOnly();

            // Clear sensitive data from memory
            Array.Clear(privateKeyBytes, 0, privateKeyBytes.Length);

            try
            {
                // Export and save public key in PEM format
                var publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
                string publicKeyPEM = ConvertToPem(publicKeyBytes, "PUBLIC KEY");
                File.WriteAllText(RSAEncryptionKey, publicKeyPEM);
            }
            catch (Exception ex)
            {
                Logger.Error($"RSA Key Generation/Testing failed: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Convert a byte array to a PEM-formatted string.
        /// </summary>
        private static string ConvertToPem(byte[] keyBytes, string keyType)
        {
            string base64Key = Convert.ToBase64String(keyBytes, Base64FormattingOptions.InsertLineBreaks);
            return $"-----BEGIN {keyType}-----\n{base64Key}\n-----END {keyType}-----\n";
        }

        public static byte[] GetKeyBytes(SecureString secureKey)
        {
            ArgumentNullException.ThrowIfNull(secureKey);

            var bstr = IntPtr.Zero;
            try
            {
                bstr = System.Runtime.InteropServices.Marshal.SecureStringToBSTR(secureKey);
                var base64String = System.Runtime.InteropServices.Marshal.PtrToStringBSTR(bstr);
                
                if (string.IsNullOrEmpty(base64String))
                    return [];

                return Convert.FromBase64String(base64String);
            }
            catch (Exception ex)
            {
                Logger.Error($"Error in GetKeyBytes: {ex.Message}");
                throw;
            }
            finally
            {
                if (bstr != IntPtr.Zero)
                    System.Runtime.InteropServices.Marshal.ZeroFreeBSTR(bstr);
            }
        }
    }
}
