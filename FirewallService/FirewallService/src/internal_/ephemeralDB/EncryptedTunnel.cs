using System.Net;
using System.Security;
using System.Text;
using FirewallService.util;
using Newtonsoft.Json;

namespace FirewallService.internal_.ephemeralDB;

public class EncryptedTunnel : IStreamableObject<EncryptedTunnel> , IDisposable
{
    public CipherSuite Suite { get; set; }
    public EncryptionProtocol EncProtocol { get; set; }
    public (AESEncryptionMode? AESMode, PaddingScheme? AESScheme, PaddingScheme? RSAScheme) EncMetadata { get; set; }
    public KeyExchangeStandard XchgStandard { get; set; }
    public TunnelType? Type { get; set; }
    public KeyFormat KFormat { get; set; }
    
    public long TunnelID { get; set; }
    public ushort PortNumber { get; set; }
    public (IPAddress Source, IPAddress Destination) Sides { get; set; }
    
    public SecureString Key { get; set; }
    public string? TLSFingerprint { get; set; }
    public string? AuthTagAlgorithm { get; set; }  // e.g., SHA256, Poly1305

    public DateTime CreatedAt { get; set; }
    public DateTime? ExpiresAt { get; set; }

    public string ToStringStream()
    {
        var payload = new
        {
            Suite = Suite.ToString(),
            EncProtocol = EncProtocol.ToString(),
            EncMetadata = new {
                AESMode = EncMetadata.AESMode?.ToString(),
                AESScheme = EncMetadata.AESScheme?.ToString(),
                RSAScheme = EncMetadata.RSAScheme?.ToString()
            },
            XchgStandard = XchgStandard.ToString(),
            Type = Type?.ToString(),
            KFormat = KFormat.ToString(),
            TunnelID,
            PortNumber,
            Sides = new {
                Source = Sides.Source.ToString(),
                Destination = Sides.Destination.ToString()
            },
            Key = Key.ToString(), // assumes Key has overridden ToString to show base64 content
            TLSFingerprint,
            AuthTagAlgorithm,
            CreatedAt = CreatedAt.ToString("o"),
            ExpiresAt = ExpiresAt?.ToString("o")
        };

        var json = JsonConvert.SerializeObject(payload);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
    }

    public override string ToString()
    {
        var payload = new
        {
            Suite = Suite.ToString(),
            EncProtocol = EncProtocol.ToString(),
            EncMetadata = new {
                AESMode = EncMetadata.AESMode?.ToString(),
                AESScheme = EncMetadata.AESScheme?.ToString(),
                RSAScheme = EncMetadata.RSAScheme?.ToString()
            },
            XchgStandard = XchgStandard.ToString(),
            Type = Type?.ToString(),
            KFormat = KFormat.ToString(),
            TunnelID,
            PortNumber,
            Sides = new {
                Source = Sides.Source.ToString(),
                Destination = Sides.Destination.ToString()
            },
            Key = Key.ToString(), // assumes Key has overridden ToString to show base64 content
            TLSFingerprint,
            AuthTagAlgorithm,
            CreatedAt = CreatedAt.ToString("o"),
            ExpiresAt = ExpiresAt?.ToString("o")
        };
        return JsonConvert.SerializeObject(payload);
    }

    public static EncryptedTunnel Parse(string sStream)
    {
        var json = Encoding.UTF8.GetString(Convert.FromBase64String(sStream));
        var obj = JsonConvert.DeserializeObject<dynamic>(json);

        return new EncryptedTunnel
        {
            Suite = Enum.Parse<CipherSuite>((string)obj?.Suite! ?? string.Empty),
            EncProtocol = Enum.Parse<EncryptionProtocol>((string)obj?.EncProtocol! ?? string.Empty),
            EncMetadata = (
                string.IsNullOrEmpty((string?)obj?.EncMetadata.AESMode) ? null : Enum.Parse<AESEncryptionMode>((string)obj.EncMetadata.AESMode),
                string.IsNullOrEmpty((string?)obj?.EncMetadata.AESScheme) ? null : Enum.Parse<PaddingScheme>((string)obj.EncMetadata.AESScheme),
                string.IsNullOrEmpty((string?)obj?.EncMetadata.RSAScheme) ? null : Enum.Parse<PaddingScheme>((string)obj.EncMetadata.RSAScheme)
            ),
            XchgStandard = Enum.Parse<KeyExchangeStandard>((string)obj?.XchgStandard! ?? string.Empty),
            Type = string.IsNullOrEmpty((string?)obj?.Type) ? null : Enum.Parse<TunnelType>((string)obj.Type),
            KFormat = Enum.Parse<KeyFormat>((string)obj?.KFormat! ?? string.Empty),
            TunnelID = (long)(obj?.TunnelID ?? long.MaxValue),
            PortNumber = (ushort)(obj?.PortNumber ?? ushort.MaxValue),
            Sides = (
                IPAddress.Parse((string)obj?.Sides.Source! ?? string.Empty),
                IPAddress.Parse((string)obj?.Sides.Destination! ?? string.Empty)
            ),
            Key = new SecureString(), // This must be rehydrated securely
            TLSFingerprint = (string?)obj?.TLSFingerprint,
            AuthTagAlgorithm = (string?)obj?.AuthTagAlgorithm,
            CreatedAt = DateTime.Parse((string)obj?.CreatedAt! ?? string.Empty),
            ExpiresAt = string.IsNullOrEmpty((string?)obj?.ExpiresAt) ? null : DateTime.Parse((string)obj.ExpiresAt)
        };
    }
    public void Dispose()
    {
        // Clear key contents
        if (Key.Length > 0)
        {
            try
            {
                // Decrypt the SecureString to plain text temporarily
                var ptr = System.Runtime.InteropServices.Marshal.SecureStringToGlobalAllocUnicode(Key);
                try
                {
                    for (var i = 0; i < Key.Length; i++)
                        System.Runtime.InteropServices.Marshal.WriteInt16(ptr, i * 2, 0); // Overwrite each character
                }
                finally
                {
                    System.Runtime.InteropServices.Marshal.ZeroFreeGlobalAllocUnicode(ptr); // Free and zero
                }
            }
            catch
            {
                // Suppress exceptions on disposal
            }

            Key.Dispose();
        }

        // Nullify references
        TLSFingerprint = null;
        AuthTagAlgorithm = null;
        Sides = default;
        EncMetadata = default;
    }
}