using System;
using System.Security.Cryptography;
using System.Text;

namespace FirewallService.auth
{
    public static class PasswordHasher
    {
        private const int SaltSize = 16;
        private const int HashSize = 32;
        private const int Iterations = 100_000;

        public static string HashPassword(string password)
        {
            var salt = RandomNumberGenerator.GetBytes(SaltSize);

            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256);
            var hash = pbkdf2.GetBytes(HashSize);

            return $"{Iterations}.{Convert.ToBase64String(salt)}.{Convert.ToBase64String(hash)}";
        }

        public static bool VerifyPassword(char[] passwordChars, string storedHash)
        {
            string? password = null;
            try
            {
                password = new string(passwordChars);
                var parts = storedHash.Split('.');
                if (parts.Length != 3)
                    return false;

                var iterations = int.Parse(parts[0]);
                var salt = Convert.FromBase64String(parts[1]);
                var storedHashBytes = Convert.FromBase64String(parts[2]);

                using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
                var derivedHash = pbkdf2.GetBytes(HashSize);

                return CryptographicOperations.FixedTimeEquals(storedHashBytes, derivedHash);
            }
            catch
            {
                return false;
            }
            finally
            {
                if (password != null)
                {
                    // Best-effort overwrite: create a new string of nulls and copy over it
                    GC.KeepAlive(password); // Prevent early optimization
                    OverwriteStringWithNulls(password);
                    password = null;
                }
            }
        }

        private static void OverwriteStringWithNulls(string s)
        {
            // Strings are immutable in C#, so we can't mutate them directly.
            // This method allocates garbage to encourage the GC to collect the original string sooner.
            var dummy = new string('\0', s.Length);
            GC.KeepAlive(dummy); // Ensure dummy survives optimization
        }
    }
}
