using PvePatcher.Core;

namespace PvePatcher.Targets;

/// <summary>Parsers puros da saída de máquina do patcher-agent.</summary>
public static class AgentOutputParser
{
    public static (OsInfo Os, string Kernel) ParseOsInfo(string output)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        var kernel = "";
        foreach (var f in Records(output))
        {
            if (f.Length >= 3 && f[0] == "O") map[f[1]] = f[2];
            else if (f.Length >= 3 && f[0] == "K") kernel = f[2];
        }
        var codename = map.GetValueOrDefault("VERSION_CODENAME");
        var os = new OsInfo(
            OsInfo.ParseDistroId(map.GetValueOrDefault("ID")),
            map.GetValueOrDefault("VERSION_ID") ?? "",
            string.IsNullOrEmpty(codename) ? null : codename,
            map.GetValueOrDefault("PRETTY_NAME") ?? map.GetValueOrDefault("ID") ?? "");
        return (os, kernel);
    }

    public static (IReadOnlyList<InstalledPackage> Installed, IReadOnlyList<PendingUpdate> Pending) ParseList(string output)
    {
        var installed = new List<InstalledPackage>();
        var updates = new List<string[]>();
        var sourceByName = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var f in Records(output))
        {
            if (f.Length >= 6 && f[0] == "I")
            {
                var source = f[2].Length == 0 ? f[1] : f[2];
                var sourceVersion = f[4].Length == 0 ? f[3] : f[4];
                installed.Add(new InstalledPackage(f[1], source, f[3], sourceVersion, NullIfEmpty(f[5])));
                sourceByName.TryAdd(f[1], source);
            }
            else if (f.Length >= 6 && f[0] == "U") updates.Add(f);
        }

        var pending = updates
            .Select(f => new PendingUpdate(f[1], sourceByName.GetValueOrDefault(f[1]) ?? f[1], f[2], f[3], NullIfEmpty(f[4]), f[5] == "1"))
            .ToList();
        return (installed, pending);
    }

    public static bool ParseRebootRequired(string output) => output.Trim() switch
    {
        "yes" => true,
        "no" => false,
        var other => throw new TargetException($"Resposta inesperada de reboot-required: '{other}'"),
    };

    private static string? NullIfEmpty(string s) => s.Length == 0 ? null : s;

    private static IEnumerable<string[]> Records(string output)
    {
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Length == 0) continue;
            yield return line.Split('\t');
        }
    }
}
