using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using FirewallService.util;

namespace FirewallService.auth.ActionAuthentication
{
    public static class TrustPhraseManager
    {
        private const string WordListPath = "/usr/share/firewall/trustphrase-words.txt";
        private const string WordListUrl = "https://raw.githubusercontent.com/tabatkins/wordle-list/main/words";
        private const string KnownGoodHash = "ba86911aea83d038d53c0999fe6cbe310c8f59d2b79626c73bd0cd0773adc320";
        private const int MinWords = 5000;

        private static List<string> _wordList = null!;
        private static SecureString _trustPhrase = null!;

        public static void Initialize()
        {
            EnsureWordListExistsAndValid();
            var phrase = GeneratePhrase();

            _trustPhrase = new SecureString();
            foreach (var c in phrase)
                _trustPhrase.AppendChar(c);
            _trustPhrase.MakeReadOnly();

            Logger.Info($"Trust Phrase for this session: {phrase}");
        }

        public static SecureString GetTrustPhrase()
        {
            if (_trustPhrase == null)
                throw new InvalidOperationException("Trust phrase not initialized.");
            return _trustPhrase;
        }

        private static void EnsureWordListExistsAndValid()
        {
            if (!File.Exists(WordListPath))
            {
                Logger.Info("Word list not found, downloading...");
                DownloadWordList();
                SetPermissions644(WordListPath);
            }

            VerifyPermissions(WordListPath);
            ValidateWordList();
        }

        private static void DownloadWordList()
        {
            using var client = new HttpClient();
            var content = client.GetStringAsync(WordListUrl).Result;

            var words = content.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(w => w.Trim().ToLowerInvariant())
                .Where(w => Regex.IsMatch(w, @"^[a-z]{4,10}$"))
                .Distinct()
                .OrderBy(w => w)
                .ToList();

            if (words.Count < MinWords)
                throw new InvalidOperationException("Downloaded word list does not contain enough unique words.");

            Directory.CreateDirectory(Path.GetDirectoryName(WordListPath)!);

            using var stream = new StreamWriter(WordListPath, false, new UTF8Encoding(true)); // with BOM
            foreach (var word in words)
                stream.WriteLine(word.Replace("\n", "").Replace("\r", "")); // force \r\n line ending

            stream.Flush();
        }

        private static void SetPermissions644(string path)
        {
            const int S_IRUSR = 0x100;
            const int S_IWUSR = 0x80;
            const int S_IRGRP = 0x20;
            const int S_IROTH = 0x4;

            int mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

            if (chmod(path, mode) != 0)
                throw new InvalidOperationException($"Failed to chmod 644 on {path}");
        }

        private static void VerifyPermissions(string path)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "/bin/bash",
                Arguments = $"-c \"stat -c %a {path}\"",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            process.WaitForExit();

            var output = process.StandardOutput.ReadToEnd().Trim();

            if (output != "644")
            {
                throw new InvalidOperationException($"Word list must have permissions 0644. Found: {output}");
            }
        }


        private static void ValidateWordList()
        {
            var hash = ComputeSHA256(WordListPath);
            if (!string.Equals(hash, KnownGoodHash, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Word list hash mismatch — possible tampering.");

            _wordList = File.ReadAllLines(WordListPath)
                .Select(w => w.Trim().ToLowerInvariant())
                .Where(w => Regex.IsMatch(w, @"^[a-z]{4,10}$"))
                .Distinct()
                .ToList();

            if (_wordList.Count < MinWords)
                throw new InvalidOperationException("Word list validation failed: not enough unique words.");
        }

        private static string GeneratePhrase()
        {
            using var rng = RandomNumberGenerator.Create();
            var i1 = GetRandomIndex(rng, _wordList.Count);
            var i2 = GetRandomIndex(rng, _wordList.Count);
            var num = GetRandomIndex(rng, 90) + 10;
            return $"{_wordList[i1].ToUpperInvariant()}-{_wordList[i2].ToUpperInvariant()}-{num:D2}";
        }

        private static int GetRandomIndex(RandomNumberGenerator rng, int maxExclusive)
        {
            var buffer = new byte[4];
            int result;
            do
            {
                rng.GetBytes(buffer);
                result = BitConverter.ToInt32(buffer, 0) & int.MaxValue;
            } while (result >= maxExclusive * (int.MaxValue / maxExclusive));
            return result % maxExclusive;
        }
        
        private static string ComputeSHA256(string filePath)
        {
            var lines = File.ReadAllLines(filePath)
                .Select(w => w.Trim().ToLowerInvariant())
                .Where(w => Regex.IsMatch(w, @"^[a-z]{4,10}$"))
                .Distinct()
                .OrderBy(w => w) // Optional: enforce deterministic order if your original hash had sorted output
                .ToList();

            string normalized = string.Join('\n', lines) + "\n"; // Add final newline if you did this before

            using var sha = SHA256.Create();
            var bytes = System.Text.Encoding.UTF8.GetBytes(normalized);
            var hash = sha.ComputeHash(bytes);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }


        // Native interop for chmod/stat
        [DllImport("libc", SetLastError = true)]
        private static extern int chmod(string path, int mode);

        [StructLayout(LayoutKind.Sequential)]
        private struct Stat
        {
            public ulong st_dev;
            public ulong st_ino;
            public ulong st_nlink;
            public uint st_mode;
            public uint st_uid;
            public uint st_gid;
            public ulong st_rdev;
            public long st_size;
            public long st_blksize;
            public long st_blocks;
            public long st_atime;
            public ulong st_atime_nsec;
            public long st_mtime;
            public ulong st_mtime_nsec;
            public long st_ctime;
            public ulong st_ctime_nsec;
            public long unused1;
            public long unused2;
            public long unused3;
        }

        [DllImport("libc", SetLastError = true)]
        private static extern int stat(string path, out Stat stat_buf);

        private static int stat_internal(string path, out Stat s) => stat(path, out s);
    }
}
