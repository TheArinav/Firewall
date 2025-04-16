using System;
using System.Diagnostics;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

using FirewallService.auth.structs;
using FirewallService.auth.ActionAuthentication;

namespace FirewallService.auth
{
    public static class FileManager
    {
        public const string DBFile = "/etc/firewall/firewall.db";
        public const string AuthFile = "/etc/firewall/authorized_users.json";
        public const string PermissionsFile = "/etc/firewall/permissions.json";
        public const string RSAEncryptionKey = "/etc/firewall/public.key";
        public const string GeneralLog = "/etc/firewall/general.log";
        public const string ActionLog = "/etc/firewall/action.log";
        public const string RSAPrivateKey = "/etc/firewall/private.key";  // Store private key securely
        public const string ShadowFile = "/etc/firewall/shadow";
        public const string TrustPhrase = "/etc/firewall/trustphrase";
        public const int KeySize = 4096;

        public static SecureString RSAKey { get; private set; }
        public static AuthManager AuthManager { get; private set; }
        public static ActionManager ActionManager { get; set; }
        public static PermissionManager PermissionManager { get; private set; }

        public static void Init()
        {
            // Database file
            if (!File.Exists(DBFile))
                using (File.Create(DBFile)) ;

            // Authorized users file
            if (!File.Exists(AuthFile))
            {
                Logger.Warn("Detected empty authentication file; No login allowed.");
                using (File.CreateText(AuthFile)) ;

                var emptyAuthObject = new AuthMainObject
                {
                    Users = []
                };

                var jsonString = JsonConvert.SerializeObject(emptyAuthObject, Formatting.Indented);
                File.WriteAllText(AuthFile, jsonString);
            }
            
            // RSA files
            if (File.Exists(RSAEncryptionKey))
                File.Delete(RSAEncryptionKey);
            if (File.Exists(RSAPrivateKey))
                File.Delete(RSAPrivateKey);
            
            // Trust-Phrase file
            if (File.Exists(TrustPhrase))
                File.Delete(TrustPhrase);
            File.CreateText(TrustPhrase);

            if (!File.Exists(ShadowFile) || File.ReadAllText(ShadowFile)=="")
            {
                Logger.CreateLock(770, 3);
                Logger.Warn("Shadow file is empty or missing. Please enter a new password:",770);
                var newPassword = Logger.Read("Password: ", 770);
                newPassword = PasswordHasher.HashPassword(newPassword);
                using var writer = new StreamWriter(ShadowFile);
                writer.WriteLine(newPassword);
                writer.Close();
                newPassword = "";
            }
            
            // Generate RSA keypair
            GenerateSecureKey(KeySize);
            
            // File Permissions
            SetFilePermissions(DBFile, "600");
            SetFilePermissions(AuthFile, "600");
            SetFilePermissions(RSAEncryptionKey, "644");
            SetFilePermissions(RSAPrivateKey, "600");
            SetFilePermissions(ShadowFile, "600");
            SetFilePermissions(TrustPhrase, "600");

            // Init Authentication Manager
            AuthManager = new AuthManager();
            
            // Init Trust-Phrase Manager
            TrustPhraseManager.Initialize();
        }

        private static void SetFilePermissions(string filePath, string permissions)
        {
            var cmd = $"chmod {permissions} {filePath} && chown root:root {filePath}";

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
            var privateKeyPEM = ConvertToPem(privateKeyBytes, "PRIVATE KEY");
            File.WriteAllText(RSAPrivateKey, privateKeyPEM);

            // Store in SecureString for additional security
            RSAKey = new SecureString();
            foreach (var c in privateKeyPEM)
                RSAKey.AppendChar(c);
            
            RSAKey.MakeReadOnly();

            // Clear sensitive data from memory
            Array.Clear(privateKeyBytes, 0, privateKeyBytes.Length);

            try
            {
                // Export and save public key in PEM format
                var publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
                var publicKeyPEM = ConvertToPem(publicKeyBytes, "PUBLIC KEY");
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
            var base64Key = Convert.ToBase64String(keyBytes, Base64FormattingOptions.InsertLineBreaks);
            return $"-----BEGIN {keyType}-----\n{base64Key}\n-----END {keyType}-----\n";
        }

        public static byte[] GetKeyBytes(SecureString secureKey)
        {
            ArgumentNullException.ThrowIfNull(secureKey);

            var bstr = IntPtr.Zero;
            try
            {
                bstr = System.Runtime.InteropServices.Marshal.SecureStringToBSTR(secureKey);
                var pemString = System.Runtime.InteropServices.Marshal.PtrToStringBSTR(bstr);

                if (string.IsNullOrEmpty(pemString))
                    return [];
                
                
                var base64Key = ExtractBase64Key(pemString);
                return Convert.FromBase64String(base64Key);
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
        /// <summary>
        /// Extracts the Base64-encoded key from a PEM file.
        /// </summary>
        private static string ExtractBase64Key(string pemKey)
        {
            var lines = pemKey.Split('\n');
            var base64Lines = lines.Select(line => line.Trim())
                .Where(trimmed => !trimmed.StartsWith("-----") && !string.IsNullOrWhiteSpace(trimmed)).ToList();
            return string.Join("", base64Lines);
        }

    }
}
