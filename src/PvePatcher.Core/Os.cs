namespace PvePatcher.Core;

/// <summary>Gerenciador de pacotes do alvo; decide o comando e o comparador de versão.</summary>
public enum OsFamily { Unknown, Apt, Dnf, Apk }

public enum Distro { Unknown, Debian, Ubuntu, AlmaLinux, Rocky, Alpine }

/// <summary>Dados do /etc/os-release (ou do guest agent get-osinfo).</summary>
/// <param name="VersionId">VERSION_ID: "12", "24.04", "9.4", "3.20.3".</param>
/// <param name="Codename">VERSION_CODENAME quando existir: "bookworm", "noble".</param>
public sealed record OsInfo(Distro Distro, string VersionId, string? Codename, string PrettyName)
{
    public OsFamily Family => Distro switch
    {
        Distro.Debian or Distro.Ubuntu => OsFamily.Apt,
        Distro.AlmaLinux or Distro.Rocky => OsFamily.Dnf,
        Distro.Alpine => OsFamily.Apk,
        _ => OsFamily.Unknown,
    };

    /// <summary>Mapeia o campo ID do os-release.</summary>
    public static Distro ParseDistroId(string? id) => id?.Trim().Trim('"').ToLowerInvariant() switch
    {
        "debian" => Distro.Debian,
        "ubuntu" => Distro.Ubuntu,
        "almalinux" => Distro.AlmaLinux,
        "rocky" => Distro.Rocky,
        "alpine" => Distro.Alpine,
        _ => Distro.Unknown,
    };
}
