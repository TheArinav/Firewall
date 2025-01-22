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

            if (!File.Exists(RSAEncryptionKey))
                File.WriteAllText(RSAEncryptionKey,"");
            GenerateSecureKey(KeySize);

            SetFilePermissions(DBFile, "600");
            SetFilePermissions(AuthFile, "600");
            SetFilePermissions(RSAEncryptionKey, "604");

            AuthManager = new AuthManager();
        }

        private static void SetFilePermissions(string filePath, string premissions)
        {
            string cmd = $"chmod {premissions} {filePath}";

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
            rsa.KeySize = keySize;
    
            // Export the private key in PKCS#8 format
            var privateKeyBytes = rsa.ExportPkcs8PrivateKey();
            string base64Key = Convert.ToBase64String(privateKeyBytes);

            // Store in SecureString
            RSAKey = new SecureString();
            foreach (char c in base64Key)
            {
                RSAKey.AppendChar(c);
            }
            RSAKey.MakeReadOnly();

            // Clear sensitive data from memory
            Array.Clear(privateKeyBytes, 0, privateKeyBytes.Length);

            // Test the key immediately to verify it works
            try 
            {
                using var testRsa = RSA.Create();
                var retrievedBytes = GetKeyBytes(RSAKey);
        
                // Try to import using both common formats
                try 
                {
                    testRsa.ImportPkcs8PrivateKey(retrievedBytes, out var bytesRead);
                    Logger.Info($"RSA Key: PKCS#8 import successful, bytes read = {bytesRead}");
                }
                catch (CryptographicException pkcs8Ex)
                {
                    // If PKCS#8 fails, try PKCS#1
                    try 
                    {
                        testRsa.ImportRSAPrivateKey(retrievedBytes, out var bytesRead);
                        Logger.Info($"RSA Key: PKCS#1 import successful, bytes read = {bytesRead}");
                    }
                    catch (CryptographicException pkcs1Ex)
                    {
                        throw new CryptographicException("Failed to import key in both PKCS#8 and PKCS#1 formats", pkcs8Ex);
                    }
                }

                // Export and save public key
                var publicKeyBytes = testRsa.ExportRSAPublicKey();
                var publicKeyBase64 = Convert.ToBase64String(publicKeyBytes);
                File.WriteAllText(RSAEncryptionKey, publicKeyBase64);
            }
            catch (Exception ex)
            {
                Logger.Error($"RSA Key Generation/Testing failed: {ex.Message}");
                throw;
            }
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
                

                var result = Convert.FromBase64String(base64String);
                return result;
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