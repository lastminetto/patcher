using PvePatcher.Core;

namespace PvePatcher.Vuln.Versioning;

/// <summary>Comparador de versões de uma família de pacotes (semântica do gerenciador nativo).</summary>
public interface IVersionComparer
{
    /// <summary>Negativo se a &lt; b, zero se iguais, positivo se a &gt; b.</summary>
    int Compare(string a, string b);
}

public static class VersionComparers
{
    public static IVersionComparer For(OsFamily family) => family switch
    {
        OsFamily.Apt => DpkgVersionComparer.Instance,
        OsFamily.Dnf => RpmVersionComparer.Instance,
        OsFamily.Apk => ApkVersionComparer.Instance,
        _ => throw new NotSupportedException($"Sem comparador de versão para a família {family}"),
    };
}
