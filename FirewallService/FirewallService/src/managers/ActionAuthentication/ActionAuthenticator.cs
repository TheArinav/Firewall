using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace FirewallService.managers.ActionAuthentication
{
    public static class ActionAuthenticator
    {
        private const int MaxAttempts = 3;
        private const int MaxPasswordLength = 128;
        
        private static readonly List<string> BlockedRequesters = [];

        public static bool ShowAuthorizationPrompt(string request, string requester)
        {
            if (BlockedRequesters.Contains(requester))
                return false;
            
            var trustPhrase = TrustPhraseManager.GetTrustPhrase();
            var trustCharArray = SecureStringToCharArray(trustPhrase);

            var _requester = EscapeShellArg(requester);
            var _request = EscapeShellArg(request);
            var trust = EscapeShellArg(new string(trustCharArray));

            var fullText = $"Request from: {_requester}\n\n" +
                           $"Request: \n{_request}\n\n" +
                           $"Trust Phrase: {trust}\n\n" +
                           $"Do you approve this action?";

            Array.Clear(trustCharArray, 0, trustCharArray.Length); // Clear trust phrase

            if (!ShowZenityQuestion("Firewall Authorization", fullText))
            {
                Logger.Warn("User denied the request.");
                BlockRequester(request);
                return false;
            }

            var attempts = 0;
            while (attempts < MaxAttempts)
            {
                var passwordChars = ShowZenityPassword($"Root Authentication. Trust phrase: {trust}");
                if (passwordChars == null)
                {
                    Logger.Warn("User closed the password prompt.");
                    BlockRequester(request);
                    return false;
                }

                var success = PasswordHasher.VerifyPassword(passwordChars, File.ReadAllText(GeneralManager.ShadowFile).Replace("\n", ""));
                Array.Clear(passwordChars, 0, passwordChars.Length); // Clear password

                if (success)
                {
                    Logger.Info("Request approved and authenticated.");
                    return true;
                }

                attempts++;
                ShowZenityError("Incorrect password. Please try again.");
            }

            Logger.Warn("Too many failed attempts. Requester blocked.");
            BlockRequester(request);
            return false;
        }

        private static bool ShowZenityQuestion(string title, string message)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "zenity",
                ArgumentList = { "--question", "--title", title, "--width", "400", "--text", message },
                UseShellExecute = false
            };

            using var process = Process.Start(psi);
            process?.WaitForExit();
            return process?.ExitCode == 0;
        }

        private static char[]? ShowZenityPassword(string title)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "zenity",
                ArgumentList = { "--password", "--title", title },
                RedirectStandardOutput = true,
                RedirectStandardInput = false,
                RedirectStandardError = false,
                UseShellExecute = false,
                StandardOutputEncoding = Encoding.UTF8
            };

            using var process = Process.Start(psi);
            if (process == null)
                return null;

            var outputBuilder = new List<char>();
            int c;
            while ((c = process.StandardOutput.Read()) != -1)
            {
                var ch = (char)c;
                if (ch is '\n' or '\r') // trim trailing newlines
                    break;
                outputBuilder.Add(ch);
            }

            process.WaitForExit();
            return process.ExitCode == 0 ? outputBuilder.ToArray() : null;
        }


        private static void ShowZenityError(string message)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "zenity",
                ArgumentList = { "--error", "--title", "Authentication Error", "--text", message },
                UseShellExecute = false
            };

            using var process = Process.Start(psi);
            process?.WaitForExit();
        }

        private static string EscapeShellArg(string input)
        {
            return input
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("`", "\\`")
                .Replace("$", "\\$")
                .Replace("!", "\\!");
        }

        private static char[] SecureStringToCharArray(SecureString? secure)
        {
            if (secure == null) 
                return [];
            var ptr = IntPtr.Zero;
            try
            {
                ptr = Marshal.SecureStringToGlobalAllocUnicode(secure);
                var length = secure.Length;
                var result = new char[length];
                Marshal.Copy(ptr, result, 0, length);
                return result;
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(ptr);
            }
        }

        private static void BlockRequester(string requester)
        {
            Logger.Warn($"Blocking future requests from: {requester}");
            BlockedRequesters.Add(requester);
        }
    }
}
