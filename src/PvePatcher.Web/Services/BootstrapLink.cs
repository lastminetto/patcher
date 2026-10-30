namespace PvePatcher.Web.Services;

/// <summary>
/// Endereço e verificação TLS do <c>curl</c> do bootstrap. Prioridade: valor salvo na tela de Configurações, depois
/// <c>Bootstrap:PublicBaseUrl</c> / <c>Bootstrap:PinAppCertificate</c> do appsettings, depois o endereço da própria página.
/// </summary>
public static class BootstrapLink
{
    /// <summary>Pinar a chave do certificado do próprio app (autoassinado, acesso direto à 8443).</summary>
    public const string TlsPin = "pin";
    /// <summary>Validação normal da cadeia (proxy com certificado que as VMs confiam).</summary>
    public const string TlsChain = "ca";

    public static string BaseUrl(string? fromSettings, string? fromConfig, string pageBase)
    {
        foreach (var c in new[] { fromSettings, fromConfig, pageBase })
            if (!string.IsNullOrWhiteSpace(c)) return c.Trim().TrimEnd('/');
        return "";
    }

    /// <summary>Pin só faz sentido em HTTPS; o modo da tela vence o do appsettings.</summary>
    public static bool UsePin(string baseUrl, string? tlsFromSettings, bool pinFromConfig) =>
        baseUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
        && tlsFromSettings switch { TlsPin => true, TlsChain => false, _ => pinFromConfig };

    /// <summary>Vazio (usa o padrão) ou URL absoluta http(s), sem query nem fragmento.</summary>
    public static bool TryNormalize(string? value, out string normalized, out string? error)
    {
        normalized = "";
        error = null;
        if (string.IsNullOrWhiteSpace(value)) return true;
        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var u) || (u.Scheme != Uri.UriSchemeHttps && u.Scheme != Uri.UriSchemeHttp))
        {
            error = "Use uma URL completa, ex.: https://patcher.exemplo.com.br";
            return false;
        }
        if (u.Query.Length > 0 || u.Fragment.Length > 0)
        {
            error = "A URL não pode ter query (?) nem fragmento (#).";
            return false;
        }
        normalized = u.GetLeftPart(UriPartial.Path).TrimEnd('/');
        return true;
    }
}
