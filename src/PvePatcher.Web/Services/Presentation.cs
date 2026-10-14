using PvePatcher.Core;

namespace PvePatcher.Web.Services;

/// <summary>Formatação e regras de exibição (sem dependência de cultura/ICU).</summary>
public static class Fmt
{
    public static string Date(DateTimeOffset? d, string zoneId = "America/Sao_Paulo") =>
        d is null ? "—" : TimeZoneInfo.ConvertTime(d.Value, CronHelper.Zone(zoneId)).ToString("dd/MM/yyyy HH:mm");

    public static string Relative(DateTimeOffset? d, DateTimeOffset now)
    {
        if (d is null) return "nunca";
        var t = now - d.Value;
        if (t < TimeSpan.Zero) return "em breve";
        if (t.TotalSeconds < 60) return "agora";
        if (t.TotalMinutes < 60) return $"há {(int)t.TotalMinutes} min";
        if (t.TotalHours < 48) return $"há {(int)t.TotalHours} h";
        return $"há {(int)t.TotalDays} dias";
    }

    public static string Until(DateTimeOffset? d, DateTimeOffset now)
    {
        if (d is null) return "—";
        var t = d.Value - now;
        if (t.TotalMinutes < 1) return "agora";
        if (t.TotalHours < 1) return $"em {(int)t.TotalMinutes} min";
        if (t.TotalHours < 48) return $"em {(int)t.TotalHours} h {t.Minutes} min";
        return $"em {(int)t.TotalDays} dias";
    }

    public static string Percent(double? v) => v is null ? "—" : (v.Value * 100).ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) + "%";
    public static string Cvss(double? v) => v is null ? "—" : v.Value.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture);

    public static string SeverityName(Severity s) => s switch
    {
        Severity.Critical => "Crítica", Severity.High => "Alta", Severity.Medium => "Média", Severity.Low => "Baixa", _ => "—",
    };

    public static string SeverityClass(Severity s) => s switch
    {
        Severity.Critical => "b-crit", Severity.High => "b-high", Severity.Medium => "b-med", Severity.Low => "b-low", _ => "b-off",
    };

    public static string StatusName(FindingStatus s) => s switch
    {
        FindingStatus.FixedByPendingUpdate => "Corrigida pela atualização",
        FindingStatus.FixNotInCandidate => "Correção fora da candidata",
        _ => "Sem correção",
    };

    public static string DistroName(Distro d) => d switch
    {
        Distro.AlmaLinux => "AlmaLinux", Distro.Rocky => "Rocky", Distro.Unknown => "?", _ => d.ToString(),
    };
}

public static class CveLinks
{
    /// <summary>Página do CVE no tracker da distro (NVD quando a distro não tem um).</summary>
    public static string For(Distro distro, string cve) => distro switch
    {
        Distro.Debian => $"https://security-tracker.debian.org/tracker/{cve}",
        Distro.Ubuntu => $"https://ubuntu.com/security/{cve}",
        Distro.Alpine => $"https://security.alpinelinux.org/vuln/{cve}",
        _ => $"https://nvd.nist.gov/vuln/detail/{cve}",
    };
}

public enum VmDisplayStatus { Unscanned, Ok, Error, NoIp, HostKeyChanged, AgentOff, Stopped }

public static class VmStatusRules
{
    public static VmDisplayStatus Compute(VmEntity vm, bool hasIp)
    {
        if (vm.State == ScanState.HostKeyChanged) return VmDisplayStatus.HostKeyChanged;
        if (!vm.IsRunning) return VmDisplayStatus.Stopped;
        if (!hasIp) return VmDisplayStatus.NoIp;
        if (vm.State == ScanState.Error) return VmDisplayStatus.Error;
        if (!vm.AgentResponding) return VmDisplayStatus.AgentOff;
        return vm.LastScanAt is null ? VmDisplayStatus.Unscanned : VmDisplayStatus.Ok;
    }

    public static (string Text, string Css) Describe(VmDisplayStatus s) => s switch
    {
        VmDisplayStatus.Ok => ("ok", "b-ok"),
        VmDisplayStatus.Error => ("erro", "b-err"),
        VmDisplayStatus.NoIp => ("sem IP", "b-warn"),
        VmDisplayStatus.HostKeyChanged => ("host key mudou", "b-err"),
        VmDisplayStatus.AgentOff => ("agent off", "b-warn"),
        VmDisplayStatus.Stopped => ("parada", "b-off"),
        _ => ("não escaneada", "b-off"),
    };
}
