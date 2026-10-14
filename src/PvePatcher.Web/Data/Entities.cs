using System.ComponentModel.DataAnnotations;
using PvePatcher.Core;

namespace PvePatcher.Web.Data;

public enum ScanState { None, Ok, Error, HostKeyChanged }

public sealed class ClusterEntity
{
    [Key] public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string EndpointsJson { get; set; } = "[]";
    public string? Fingerprint { get; set; }
    public DateTimeOffset? LastDiscoveryAt { get; set; }
    public string? LastDiscoveryError { get; set; }

    public List<string> Endpoints
    {
        get => Json.Deserialize<List<string>>(EndpointsJson) ?? [];
        set => EndpointsJson = Json.Serialize(value);
    }

    public ClusterConfig ToConfig() => new(Id, Name, Endpoints, string.IsNullOrWhiteSpace(Fingerprint) ? null : Fingerprint);
}

/// <summary>Versão resumida do scan guardada no banco (a lista completa de instalados não é persistida).</summary>
public sealed record StoredScan(OsInfo Os, string Kernel, List<PendingUpdate> Pending, bool RebootRequired, DateTimeOffset ScannedAt, int InstalledCount);

/// <summary>Chave de uma VM na aplicação.</summary>
public readonly record struct VmKey(string ClusterId, int VmId)
{
    public override string ToString() => $"{ClusterId}/{VmId}";
}

/// <summary>Estado atual de uma VM: dados do discovery + último scan + último log. Sem histórico.</summary>
public sealed class VmEntity
{
    public string ClusterId { get; set; } = "";
    public int VmId { get; set; }
    public string Node { get; set; } = "";
    public string Name { get; set; } = "";
    public string Status { get; set; } = "";
    public bool AgentResponding { get; set; }
    public string? OsJson { get; set; }
    public string NicsJson { get; set; } = "[]";
    public Distro Distro { get; set; }

    public IpOverrideMode IpOverrideMode { get; set; }
    public string? IpOverrideValue { get; set; }
    public int SshPort { get; set; } = 22;
    public string? KnownHostKey { get; set; }
    public string? PendingHostKey { get; set; }

    public ScanState State { get; set; }
    public string? LastError { get; set; }
    public DateTimeOffset? LastScanAt { get; set; }
    public string? ScanJson { get; set; }
    public string? FindingsJson { get; set; }

    // Contadores denormalizados para a lista (CVEs distintas corrigíveis pelas atualizações pendentes).
    public int PendingCount { get; set; }
    public int HeldBackCount { get; set; }
    public int CriticalFixable { get; set; }
    public int HighFixable { get; set; }
    public int MediumFixable { get; set; }
    public int LowFixable { get; set; }
    public int KevFixable { get; set; }
    public int UnfixedCount { get; set; }
    public bool RebootRequired { get; set; }

    public string? LastJobLog { get; set; }
    public DateTimeOffset? LastJobAt { get; set; }
    public string? LastJobKind { get; set; }
    public string? LastJobResult { get; set; }

    public bool IsRunning => Status == "running";
    public VmKey Key => new(ClusterId, VmId);

    public OsInfo? Os
    {
        get => Json.Deserialize<OsInfo>(OsJson);
        set { OsJson = value is null ? null : Json.Serialize(value); if (value is not null) Distro = value.Distro; }
    }

    public List<GuestNic> Nics
    {
        get => Json.Deserialize<List<NicDto>>(NicsJson)?.Select(n => n.ToNic()).ToList() ?? [];
        set => NicsJson = Json.Serialize(value.Select(NicDto.From).ToList());
    }

    public StoredScan? Scan => Json.Deserialize<StoredScan>(ScanJson);
    public List<CveFinding> Findings => Json.Deserialize<List<CveFinding>>(FindingsJson) ?? [];

    public DiscoveredVm ToDiscovered() => new(ClusterId, Node, VmId, Name, Status, Nics, Os, AgentResponding);

    /// <summary>Aplica o resultado de um scan e recalcula os contadores.</summary>
    public void ApplyScan(HostScan scan, IReadOnlyList<CveFinding> findings)
    {
        ScanJson = Json.Serialize(new StoredScan(scan.Os, scan.Kernel, scan.Pending.ToList(), scan.RebootRequired, scan.ScannedAt, scan.Installed.Count));
        FindingsJson = Json.Serialize(findings);
        LastScanAt = scan.ScannedAt;
        RebootRequired = scan.RebootRequired;
        Os = scan.Os;
        var c = VmCounters.Compute(findings, scan.Pending.Count, scan.Pending.Count(p => p.HeldBack));
        PendingCount = c.Pending; HeldBackCount = c.HeldBack;
        CriticalFixable = c.Critical; HighFixable = c.High; MediumFixable = c.Medium; LowFixable = c.Low;
        KevFixable = c.Kev; UnfixedCount = c.Unfixed;
        State = ScanState.Ok;
        LastError = null;
    }
}

public sealed record NicDto(string Name, string? Mac, List<string> Addresses)
{
    public static NicDto From(GuestNic n) => new(n.Name, n.Mac, n.Addresses.Select(a => a.ToString()).ToList());

    public GuestNic ToNic() => new(Name, Mac,
        Addresses.Select(a => System.Net.IPAddress.TryParse(a, out var ip) ? ip : null).OfType<System.Net.IPAddress>().ToList());
}

public sealed record VmCounters(int Pending, int HeldBack, int Critical, int High, int Medium, int Low, int Kev, int Unfixed)
{
    /// <summary>CVEs distintas por severidade entre as corrigíveis pela atualização pendente.</summary>
    public static VmCounters Compute(IReadOnlyList<CveFinding> findings, int pending, int heldBack)
    {
        var fix = findings.Where(f => f.Status == FindingStatus.FixedByPendingUpdate)
            .GroupBy(f => f.CveId)
            .Select(g => (Sev: g.Max(f => f.Severity), Kev: g.Any(f => f.Kev)))
            .ToList();
        return new VmCounters(
            pending, heldBack,
            fix.Count(x => x.Sev == Severity.Critical),
            fix.Count(x => x.Sev == Severity.High),
            fix.Count(x => x.Sev == Severity.Medium),
            fix.Count(x => x.Sev is Severity.Low or Severity.Unknown),
            fix.Count(x => x.Kev),
            findings.Where(f => f.Status == FindingStatus.Unfixed).Select(f => f.CveId).Distinct().Count());
    }
}

public sealed class SettingEntity
{
    [Key] public string Key { get; set; } = "";
    public string Value { get; set; } = "";
}
