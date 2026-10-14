using System.Security.Cryptography;

namespace PvePatcher.Targets;

public static class HostKeyFingerprint
{
    /// <summary>Formato do OpenSSH: "SHA256:" + base64 sem padding do hash do blob da chave pública.</summary>
    public static string Sha256(byte[] hostKeyBlob) =>
        "SHA256:" + Convert.ToBase64String(SHA256.HashData(hostKeyBlob)).TrimEnd('=');
}
