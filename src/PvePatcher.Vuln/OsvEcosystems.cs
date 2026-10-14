using System.Text.RegularExpressions;
using PvePatcher.Core;

namespace PvePatcher.Vuln;

/// <summary>Mapeia o SO do alvo para o nome de ecossistema do OSV (campo package.ecosystem).</summary>
public static partial class OsvEcosystems
{
    public static string? FromOs(OsInfo os)
    {
        switch (os.Distro)
        {
            case Distro.Debian:
            {
                var major = Major(os.VersionId) ?? os.Codename?.ToLowerInvariant() switch
                {
                    "buster" => "10",
                    "bullseye" => "11",
                    "bookworm" => "12",
                    "trixie" => "13",
                    "forky" => "14",
                    _ => null,
                };
                return major is null ? null : $"Debian:{major}";
            }
            case Distro.Ubuntu:
            {
                var m = UbuntuRegex().Match(os.VersionId ?? "");
                if (!m.Success) return null;
                var year = int.Parse(m.Groups[1].Value);
                var lts = m.Groups[2].Value == "04" && year % 2 == 0;
                return $"Ubuntu:{m.Groups[1].Value}.{m.Groups[2].Value}{(lts ? ":LTS" : "")}";
            }
            case Distro.AlmaLinux:
                return Major(os.VersionId) is { } a ? $"AlmaLinux:{a}" : null;
            case Distro.Rocky:
                return Major(os.VersionId) is { } r ? $"Rocky Linux:{r}" : null;
            case Distro.Alpine:
            {
                var m = AlpineRegex().Match(os.VersionId ?? "");
                return m.Success ? $"Alpine:v{m.Groups[1].Value}.{m.Groups[2].Value}" : null;
            }
            default:
                return null;
        }
    }

    /// <summary>Ecossistema "pai" do dump all.zip: "Debian:12" → "Debian".</summary>
    public static string Parent(string ecosystem)
    {
        var i = ecosystem.IndexOf(':');
        return i < 0 ? ecosystem : ecosystem[..i];
    }

    private static string? Major(string? versionId)
    {
        var m = MajorRegex().Match(versionId ?? "");
        return m.Success ? m.Groups[1].Value : null;
    }

    [GeneratedRegex(@"^\s*(\d+)")]
    private static partial Regex MajorRegex();

    [GeneratedRegex(@"^\s*(\d{2})\.(\d{2})")]
    private static partial Regex UbuntuRegex();

    [GeneratedRegex(@"^\s*v?(\d+)\.(\d+)")]
    private static partial Regex AlpineRegex();
}
