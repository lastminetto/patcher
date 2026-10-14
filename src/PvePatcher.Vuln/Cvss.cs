namespace PvePatcher.Vuln;

/// <summary>Nota base CVSS v3.0/v3.1 calculada a partir do vetor (a v4.0 exige tabelas; vem do NVD).</summary>
public static class Cvss
{
    public static double? ScoreV3(string? vector)
    {
        if (string.IsNullOrWhiteSpace(vector) || !vector.StartsWith("CVSS:3.", StringComparison.Ordinal)) return null;

        var m = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var part in vector.Split('/').Skip(1))
        {
            var kv = part.Split(':');
            if (kv.Length == 2) m[kv[0]] = kv[1];
        }

        if (!m.TryGetValue("S", out var scope) || (scope != "U" && scope != "C")) return null;
        var changed = scope == "C";

        double? av = Pick(m, "AV", ("N", 0.85), ("A", 0.62), ("L", 0.55), ("P", 0.2));
        double? ac = Pick(m, "AC", ("L", 0.77), ("H", 0.44));
        double? pr = changed
            ? Pick(m, "PR", ("N", 0.85), ("L", 0.68), ("H", 0.5))
            : Pick(m, "PR", ("N", 0.85), ("L", 0.62), ("H", 0.27));
        double? ui = Pick(m, "UI", ("N", 0.85), ("R", 0.62));
        double? c = Pick(m, "C", ("H", 0.56), ("L", 0.22), ("N", 0));
        double? i = Pick(m, "I", ("H", 0.56), ("L", 0.22), ("N", 0));
        double? a = Pick(m, "A", ("H", 0.56), ("L", 0.22), ("N", 0));
        if (av is null || ac is null || pr is null || ui is null || c is null || i is null || a is null) return null;

        var iss = 1 - (1 - c.Value) * (1 - i.Value) * (1 - a.Value);
        var impact = changed
            ? 7.52 * (iss - 0.029) - 3.25 * Math.Pow(iss - 0.02, 15)
            : 6.42 * iss;
        var exploitability = 8.22 * av.Value * ac.Value * pr.Value * ui.Value;

        if (impact <= 0) return 0;
        var raw = changed ? Math.Min(1.08 * (impact + exploitability), 10) : Math.Min(impact + exploitability, 10);
        return RoundUp(raw);
    }

    private static double? Pick(Dictionary<string, string> m, string key, params (string Code, double Weight)[] table)
    {
        if (!m.TryGetValue(key, out var v)) return null;
        foreach (var (code, weight) in table)
            if (code == v) return weight;
        return null;
    }

    // Roundup do CVSS 3.1 (evita erros de ponto flutuante)
    private static double RoundUp(double x)
    {
        var n = (long)Math.Round(x * 100000);
        return n % 10000 == 0 ? n / 100000.0 : (Math.Floor(n / 10000.0) + 1) / 10.0;
    }
}
