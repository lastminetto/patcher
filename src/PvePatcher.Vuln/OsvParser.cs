using System.Text.Json;
using System.Text.RegularExpressions;
using PvePatcher.Core;

namespace PvePatcher.Vuln;

/// <param name="Introduced">Null = desde sempre ("0").</param>
/// <param name="Fixed">Null junto com LastAffected null = sem correção publicada.</param>
public sealed record OsvRange(
    string Ecosystem,
    string Package,
    string? Introduced,
    string? Fixed,
    string? LastAffected,
    string? DistroSeverity);

public sealed record OsvRecord(
    string Id,
    bool IsAdvisory,
    IReadOnlyList<string> CveIds,
    string? Summary,
    string? CvssVector,
    double? CvssScore,
    IReadOnlyList<OsvRange> Ranges);

/// <summary>Converte um registro OSV (um JSON por vulnerabilidade) para linhas normalizadas.</summary>
public static partial class OsvParser
{
    private static readonly string[] AdvisoryPrefixes = ["DSA-", "DLA-", "DTSA-", "USN-", "ALSA-", "RLSA-", "RXSA-"];

    /// <summary>
    /// Null se o registro foi retirado, não tem CVE (ex.: ALBA/ALEA, correções de bug) ou
    /// nenhum affected[] pertence aos ecossistemas aceitos por <paramref name="keepEcosystem"/>.
    /// </summary>
    public static OsvRecord? Parse(ReadOnlyMemory<byte> json, Func<string, bool> keepEcosystem)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object) return null;
        if (root.TryGetProperty("withdrawn", out _)) return null;

        var id = Str(root, "id");
        if (id is null) return null;

        var affectedRanges = new List<OsvRange>();
        if (root.TryGetProperty("affected", out var affected) && affected.ValueKind == JsonValueKind.Array)
        {
            foreach (var aff in affected.EnumerateArray())
                ReadAffected(aff, keepEcosystem, affectedRanges, TopLevelSeverity(root));
        }
        if (affectedRanges.Count == 0) return null;

        var cves = new SortedSet<string>(StringComparer.Ordinal);
        AddCve(cves, id);
        foreach (var field in (ReadOnlySpan<string>)["aliases", "upstream", "related"])
        {
            if (!root.TryGetProperty(field, out var arr) || arr.ValueKind != JsonValueKind.Array) continue;
            foreach (var e in arr.EnumerateArray())
                if (e.ValueKind == JsonValueKind.String) AddCve(cves, e.GetString()!);
        }
        if (cves.Count == 0) return null;

        var summary = Str(root, "summary");
        if (string.IsNullOrWhiteSpace(summary))
        {
            var details = Str(root, "details");
            if (!string.IsNullOrWhiteSpace(details))
            {
                var line = details.Trim().Split('\n', 2)[0].Trim();
                summary = line.Length > 300 ? line[..300] : line;
            }
        }

        string? vector = null;
        if (root.TryGetProperty("severity", out var sev) && sev.ValueKind == JsonValueKind.Array)
        {
            foreach (var s in sev.EnumerateArray())
            {
                var type = Str(s, "type");
                var score = Str(s, "score");
                if (score is null) continue;
                if (type == "CVSS_V3" && (vector is null || !vector.StartsWith("CVSS:3", StringComparison.Ordinal))) vector = score;
                else if (type == "CVSS_V4" && vector is null) vector = score;
            }
        }

        var isAdvisory = AdvisoryPrefixes.Any(p => id.StartsWith(p, StringComparison.Ordinal));
        if (isAdvisory && SeverityFromSummary(summary) is { } fromSummary)
        {
            for (var k = 0; k < affectedRanges.Count; k++)
                if (affectedRanges[k].DistroSeverity is null)
                    affectedRanges[k] = affectedRanges[k] with { DistroSeverity = fromSummary };
        }
        return new OsvRecord(id, isAdvisory, cves.ToList(), summary, vector, Cvss.ScoreV3(vector), affectedRanges);
    }

    private static void ReadAffected(JsonElement aff, Func<string, bool> keep, List<OsvRange> output, string? topSeverity)
    {
        if (!aff.TryGetProperty("package", out var pkg)) return;
        var ecosystem = Str(pkg, "ecosystem");
        var name = Str(pkg, "name");
        if (ecosystem is null || name is null || !keep(ecosystem)) return;
        if (!aff.TryGetProperty("ranges", out var ranges) || ranges.ValueKind != JsonValueKind.Array) return;

        var severity = DistroSeverity(aff) ?? topSeverity;

        foreach (var range in ranges.EnumerateArray())
        {
            if (Str(range, "type") != "ECOSYSTEM") continue;
            if (!range.TryGetProperty("events", out var events) || events.ValueKind != JsonValueKind.Array) continue;

            string? introduced = null;
            var open = false;
            foreach (var ev in events.EnumerateArray())
            {
                if (ev.TryGetProperty("introduced", out var i))
                {
                    if (open) output.Add(new OsvRange(ecosystem, name, introduced, null, null, severity));
                    var v = i.GetString();
                    introduced = v is null or "0" ? null : v;
                    open = true;
                }
                else if (ev.TryGetProperty("fixed", out var f))
                {
                    output.Add(new OsvRange(ecosystem, name, introduced, f.GetString(), null, severity));
                    introduced = null;
                    open = false;
                }
                else if (ev.TryGetProperty("last_affected", out var l))
                {
                    output.Add(new OsvRange(ecosystem, name, introduced, null, l.GetString(), severity));
                    introduced = null;
                    open = false;
                }
            }
            if (open) output.Add(new OsvRange(ecosystem, name, introduced, null, null, severity));
        }
    }

    // Debian: urgency; outros: severity em ecosystem_specific
    private static string? DistroSeverity(JsonElement aff)
    {
        if (!aff.TryGetProperty("ecosystem_specific", out var es) || es.ValueKind != JsonValueKind.Object) return null;
        return Clean(Str(es, "urgency") ?? Str(es, "severity"));
    }

    // Ubuntu: severity[{type:"Ubuntu", score:"medium"}]
    private static string? TopLevelSeverity(JsonElement root)
    {
        if (!root.TryGetProperty("severity", out var sev) || sev.ValueKind != JsonValueKind.Array) return null;
        foreach (var s in sev.EnumerateArray())
            if (Str(s, "type") is { } t && !t.StartsWith("CVSS", StringComparison.Ordinal))
                return Clean(Str(s, "score"));
        return null;
    }

    private static string? Clean(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        s = s.Trim();
        return s.Equals("not yet assigned", StringComparison.OrdinalIgnoreCase)
            || s.Equals("end-of-life", StringComparison.OrdinalIgnoreCase)
            || s.Equals("unknown", StringComparison.OrdinalIgnoreCase)
            ? null : s;
    }

    private static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() : null;

    private static void AddCve(ISet<string> set, string raw)
    {
        var m = CveRegex().Match(raw);
        if (m.Success) set.Add(m.Value.ToUpperInvariant());
    }

    [GeneratedRegex(@"CVE-\d{4}-\d{4,}", RegexOptions.IgnoreCase)]
    private static partial Regex CveRegex();

    /// <summary>Texto de severidade da distro → <see cref="Severity"/>.</summary>
    public static Severity MapDistroSeverity(string? text) => text?.Trim().ToLowerInvariant() switch
    {
        "critical" => Severity.Critical,
        "high" or "important" => Severity.High,
        "medium" or "moderate" => Severity.Medium,
        "low" or "negligible" or "unimportant" => Severity.Low,
        _ => Severity.Unknown,
    };

    /// <summary>ALSA/RLSA trazem a severidade no início do summary: "Important: firefox security update".</summary>
    public static string? SeverityFromSummary(string? summary)
    {
        if (summary is null) return null;
        var i = summary.IndexOf(':');
        if (i <= 0 || i > 12) return null;
        var head = summary[..i].Trim();
        return MapDistroSeverity(head) != Severity.Unknown ? head : null;
    }
}
