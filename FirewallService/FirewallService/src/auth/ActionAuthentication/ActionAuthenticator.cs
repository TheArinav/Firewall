using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace FirewallService.auth.ActionAuthentication
{
    public static class ActionAuthenticator
    {
        private const int MaxAttempts = 3;

        public static bool ShowAuthorizationPrompt(string request, string requester)
        {
            var trustPhrase = TrustPhraseManager.GetTrustPhrase();
            var unsecurePhrase = SecureStringToString(trustPhrase);

            var _requester = EscapeShellArg(requester);
            var _request = EscapeShellArg(request);
            var trust = EscapeShellArg(unsecurePhrase);

            var fullText = $"Request from: {_requester}\n\n" +
                           $"Request: {_request}\n\n" +
                           $"Trust Phrase: {trust}\n\n" +
                           $"Do you approve this action?";

            if (!ShowZenityQuestion("Firewall Authorization", fullText))
            {
                Logger.Warn("User denied the request.");
                BlockRequester(request);
                return false;
            }

            var attempts = 0;
            while (attempts < MaxAttempts)
            {
                var password = ShowZenityPassword("Root Authentication");

                if (string.IsNullOrWhiteSpace(password))
                {
                    Logger.Warn("User closed the password prompt.");
                    BlockRequester(request);
                    return false;
                }

                if (ValidateRootPassword(password))
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

        private static string? ShowZenityPassword(string title)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "zenity",
                ArgumentList = { "--password", "--title", title },
                RedirectStandardOutput = true,
                UseShellExecute = false
            };

            using var process = Process.Start(psi);
            if (process == null)
                return null;

            var output = process.StandardOutput.ReadToEnd().Trim();
            process.WaitForExit();

            return process.ExitCode == 0 ? output : null;
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
        private static bool ValidateRootPassword(string password)
        {
            // TODO: Check Against shadow
            return false;
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

        private static string SecureStringToString(SecureString secure)
        {
            if (secure == null) return string.Empty;
            var ptr = IntPtr.Zero;
            try
            {
                ptr = Marshal.SecureStringToGlobalAllocUnicode(secure);
                return Marshal.PtrToStringUni(ptr) ?? "";
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(ptr);
            }
        }

        private static void BlockRequester(string requester)
        {
            // TODO: Block the requester from trying again (e.g. denylist file or memory map)
            Logger.Warn($"Blocking future requests from: {requester}");
        }
    }
}
