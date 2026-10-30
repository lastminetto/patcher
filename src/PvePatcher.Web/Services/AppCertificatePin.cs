using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PvePatcher.Web.Services;

/// <summary>
/// Pin do certificado que o Kestrel serve (SHA-256 da SubjectPublicKeyInfo, base64), para o
/// <c>curl --pinnedpubkey</c> do bootstrap: com certificado autoassinado o <c>-k</c> aceita a cadeia e o pin barra MITM.
/// </summary>
public sealed class AppCertificatePin(IConfiguration config, ILogger<AppCertificatePin> log)
{
    private readonly Lock _gate = new();
    private (string Path, DateTime Stamp, string? Pin)? _cache;

    /// <summary>Pin atual, ou null sem certificado configurado (ex.: dev em HTTP) ou se o PEM não pôde ser lido.</summary>
    public string? Current()
    {
        var path = config["Kestrel:Certificates:Default:Path"];
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return null;
        try
        {
            var stamp = File.GetLastWriteTimeUtc(path);
            lock (_gate)
            {
                if (_cache is { } c && c.Path == path && c.Stamp == stamp) return c.Pin;
                var pin = Compute(File.ReadAllText(path));
                _cache = (path, stamp, pin);
                return pin;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException)
        {
            log.LogWarning(ex, "Não foi possível ler o certificado {Path} para o pin do bootstrap", path);
            return null;
        }
    }

    /// <summary>Mesmo valor de <c>openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64</c>.</summary>
    public static string Compute(string certPem)
    {
        using var cert = X509Certificate2.CreateFromPem(certPem);
        return Convert.ToBase64String(SHA256.HashData(cert.PublicKey.ExportSubjectPublicKeyInfo()));
    }
}
