namespace FirewallService.auth;

using System;
using System.Security.Cryptography;
using System.Text;

public static class PasswordHasher
{
    private const int SaltSize = 16;  // 128 bits
    private const int HashSize = 32;  // 256 bits
    private const int Iterations = 100_000;

    // Returns a string: {iterations}.{base64Salt}.{base64Hash}
    public static string HashPassword(string password)
    {
        // Generate random salt
        var salt = RandomNumberGenerator.GetBytes(SaltSize);

        // Derive the hash
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256);
        var hash = pbkdf2.GetBytes(HashSize);

        return $"{Iterations}.{Convert.ToBase64String(salt)}.{Convert.ToBase64String(hash)}";
    }

    public static bool VerifyPassword(string password, string storedHash)
    {
        try
        {
            var parts = storedHash.Split('.');
            if (parts.Length != 3)
                return false;

            var iterations = int.Parse(parts[0]);
            var salt = Convert.FromBase64String(parts[1]);
            var storedHashBytes = Convert.FromBase64String(parts[2]);

            // Re-derive hash with the provided password and salt
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
            var derivedHash = pbkdf2.GetBytes(HashSize);

            return CryptographicOperations.FixedTimeEquals(storedHashBytes, derivedHash);
        }
        catch
        {
            return false;
        }
    }
}
