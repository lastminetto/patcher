namespace PvePatcher.Core;

public enum Severity { Unknown, Low, Medium, High, Critical }

public enum FindingStatus
{
    /// <summary>instalada &lt; fixed ≤ candidata: a atualização pendente corrige.</summary>
    FixedByPendingUpdate,
    /// <summary>Existe versão corrigida, mas a candidata do repositório não chega nela.</summary>
    FixNotInCandidate,
    /// <summary>Sem versão corrigida publicada pela distro.</summary>
    Unfixed,
}

/// <param name="AdvisoryId">DSA/DLA/USN/ALSA/RLSA quando o CVE vier de um aviso; senão null.</param>
/// <param name="Package">Pacote binário instalado afetado (um finding por binário).</param>
/// <param name="DistroSeverity">Texto da distro: "high", "Important", "unimportant"...</param>
public sealed record CveFinding(
    string CveId,
    string? AdvisoryId,
    string Package,
    string SourcePackage,
    string InstalledVersion,
    string? FixedVersion,
    string? CandidateVersion,
    FindingStatus Status,
    double? Cvss,
    string? CvssVector,
    bool Kev,
    double? Epss,
    string? DistroSeverity,
    Severity Severity,
    string? Summary);

public sealed record SeverityThresholds(
    double CriticalCvss = 9.0,
    double HighCvss = 7.0,
    double HighEpss = 0.5,
    double MediumCvss = 4.0);

public interface IVulnerabilityMatcher
{
    /// <summary>Cruza os pacotes instalados/pendentes do scan com a base local. Não acessa a rede.</summary>
    Task<IReadOnlyList<CveFinding>> MatchAsync(HostScan scan, SeverityThresholds thresholds, CancellationToken ct);
}

public sealed record FeedState(string Name, DateTimeOffset? UpdatedAt, int Records, string? LastError);

public interface IVulnFeedUpdater
{
    /// <summary>Baixa/atualiza OSV das releases em uso, KEV e EPSS. NVD é enriquecido sob demanda para os CVEs encontrados.</summary>
    Task UpdateAsync(IReadOnlyCollection<OsInfo> releasesInUse, CancellationToken ct);

    /// <summary>Busca CVSS no NVD para CVEs ainda sem nota (respeitando rate limit).</summary>
    Task EnrichAsync(IReadOnlyCollection<string> cveIds, CancellationToken ct);

    Task<IReadOnlyList<FeedState>> GetStatusAsync(CancellationToken ct);
}
