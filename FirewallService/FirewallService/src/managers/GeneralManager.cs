using System;
using System.Diagnostics;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using FirewallService.managers.ActionAuthentication;
using FirewallService.managers.structs;

namespace FirewallService.managers
{
    public static class GeneralManager
    {
        public const string DBFile = "/etc/firewall/firewall.db";
        public const string AuthFile = "/etc/firewall/authorized_users.json";
        public const string PermissionsFile = "/etc/firewall/permissions.json";
        public const string RSAEncryptionKeyFile = "/etc/firewall/public.key";
        public const string GeneralLogFile = "/etc/firewall/general.log";
        public const string ActionLogFile = "/etc/firewall/action.log";
        public const string RSAPrivateKeyFile = "/etc/firewall/private.key";  // Store private key securely
        public const string ShadowFile = "/etc/firewall/shadow";
        public const string TrustPhraseFile = "/etc/firewall/trustphrase";
        public const int RSAKeySize = 4096;

        public static SecureString RSAKey { get; private set; } 
        public static AuthManager AuthManager { get; private set; } = null!;
        public static ActionManager ActionManager { get; set; } = null!;
        
        public static DbManager DbManager { get; set; } = null!;


        public static void Init()
        {
            // Database file
            if (!File.Exists(DBFile))
                using (File.Create(DBFile)) ;
            DbManager = new();
            if ((new FileInfo(DBFile)).Length == 0)
                DbManager.Init();

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
            if (File.Exists(RSAEncryptionKeyFile))
                File.Delete(RSAEncryptionKeyFile);
            if (File.Exists(RSAPrivateKeyFile))
                File.Delete(RSAPrivateKeyFile);
            
            // Trust-Phrase file
            if (File.Exists(TrustPhraseFile))
                File.Delete(TrustPhraseFile);
            File.CreateText(TrustPhraseFile);

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
            GenerateSecureKey(RSAKeySize);
            
            // File Permissions
            SetFilePermissions(DBFile, "600");
            SetFilePermissions(AuthFile, "600");
            SetFilePermissions(RSAEncryptionKeyFile, "644");
            SetFilePermissions(RSAPrivateKeyFile, "600");
            SetFilePermissions(ShadowFile, "600");
            SetFilePermissions(TrustPhraseFile, "600");

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
            File.WriteAllText(RSAPrivateKeyFile, privateKeyPEM);

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
                File.WriteAllText(RSAEncryptionKeyFile, publicKeyPEM);
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
