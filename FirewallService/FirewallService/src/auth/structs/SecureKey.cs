using System;
using System.Collections;
using System.Security;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;

namespace FirewallService.auth.structs
{
    public struct SecureKey : IEquatable<SecureKey>, IDisposable, IEnumerable<byte>, ICloneable
    {
        // Temporary storage (transient, null unless Open() is called)
        private byte[] bytes;

        // Permanent storage (base64 encoded string of the token)
        private SecureString tokenStorage;

        // Helper constants
        public const int sizeBytes = 32;
        public const int sizeBits = 256;
        public const int sizeBase64 = 44;

        public SecureKey(bool empty = false)
        {
            bytes = new byte[sizeBytes];
            tokenStorage = new SecureString();
            if (!empty)
                RandomNumberGenerator.Fill(bytes);
            Close();
        }

        public byte this[int index]
        {
            get => bytes[index];
            set => bytes[index] = value;
        }
        
        public void Open()
        {
            if (tokenStorage == null)
                return;

            string? base64;
            var ptr = IntPtr.Zero;
            try
            {
                ptr = Marshal.SecureStringToGlobalAllocUnicode(tokenStorage);
                base64 = Marshal.PtrToStringUni(ptr);
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                    Marshal.ZeroFreeGlobalAllocUnicode(ptr);
            }

            bytes = Convert.FromBase64String(base64);
        }

        public void Close()
        {
            if (bytes == null)
                return;

            var base64 = Convert.ToBase64String(bytes);
            tokenStorage = new SecureString();
            foreach (var c in base64)
                tokenStorage.AppendChar(c);
            tokenStorage.MakeReadOnly();

            Array.Clear(bytes, 0, bytes.Length);
        }

        public bool Equals(SecureKey other)
        {
            Open();
            other.Open();

            var areEqual = true;
            for (var i = 0; i < sizeBytes; i++)
                if (this[i] != other[i])
                {
                    areEqual = false;
                    break;
                }

            Close();
            other.Close();

            return areEqual;
        }

        public override string ToString()
        {
            var ptr = IntPtr.Zero;
            try
            {
                ptr = Marshal.SecureStringToGlobalAllocUnicode(tokenStorage);
                return Marshal.PtrToStringUni(ptr);
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                    Marshal.ZeroFreeGlobalAllocUnicode(ptr);
            }
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        public IEnumerator<byte> GetEnumerator()
        {
            Open();
            try
            {
                for (var i = 0; i < sizeBytes; i++)
                    yield return bytes[i];
            }
            finally
            {
                Close();
            }
        }
        
        public override int GetHashCode()
        {
            // Uses the first 4 bytes as a simple hash seed
            Open();
            var hash = BitConverter.ToInt32(bytes, 0);
            Close();
            return hash;
        }

        public void Dispose()
        {
            if (bytes != null)
            {
                Array.Clear(bytes, 0, bytes.Length);
                bytes = null;
            }

            if (tokenStorage == null) return;
            
            tokenStorage.Dispose();
            tokenStorage = null;
        }

        public object Clone()
        {
            var clone = new SecureKey(true);
            Open();
            clone.Open();
            for (var i=0; i<sizeBytes; i++)
                clone[i] = bytes[i];
            Close();
            clone.Close();
            return clone;
        }

        public byte[]? GetBytes()
        {
            return this.bytes;
        }
    }
}
