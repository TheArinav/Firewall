namespace FirewallService.internal_.ephemeralDB;

public enum PaddingScheme
{
    RSA_PKCS1_v1_5,
    RSA_OAEP_SHA1,
    RSA_OAEP_SHA256,
    RSA_PSS,
    AES_PKCS7,
    AES_ANSI_X923,
    AES_ISO_7816,
    AES_None
}