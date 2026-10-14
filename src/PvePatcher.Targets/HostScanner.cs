using Microsoft.Extensions.Options;
using PvePatcher.Core;

namespace PvePatcher.Targets;

public sealed class HostScanner(IOptions<SshOptions> options) : IHostScanner
{
    private readonly SshOptions _o = options.Value;

    public async Task<HostScan> ScanAsync(ITargetSession session, Action<string>? onLine, CancellationToken ct)
    {
        var query = TimeSpan.FromSeconds(_o.QueryTimeoutSeconds);

        var osOut = await RunOkAsync(session, "osinfo", null, query, ct).ConfigureAwait(false);
        var (os, kernel) = AgentOutputParser.ParseOsInfo(osOut);
        if (os.Family == OsFamily.Unknown)
            throw new TargetException($"Distribuição não suportada: {os.PrettyName}");

        await RunOkAsync(session, "refresh", onLine, TimeSpan.FromMinutes(_o.RefreshTimeoutMinutes), ct).ConfigureAwait(false);

        var listOut = await RunOkAsync(session, "list", null, query, ct).ConfigureAwait(false);
        var (installed, pending) = AgentOutputParser.ParseList(listOut);

        var rebootOut = await RunOkAsync(session, "reboot-required", null, query, ct).ConfigureAwait(false);
        return new HostScan(os, kernel, installed, pending, AgentOutputParser.ParseRebootRequired(rebootOut), DateTimeOffset.UtcNow);
    }

    private static async Task<string> RunOkAsync(ITargetSession s, string sub, Action<string>? onLine, TimeSpan timeout, CancellationToken ct)
    {
        var r = await s.RunAgentAsync(sub, [], onLine, timeout, ct).ConfigureAwait(false);
        if (r.ExitCode != 0)
            throw new TargetException($"patcher-agent {sub} falhou (exit {r.ExitCode}): {Tail(r.StdErr)}");
        return r.StdOut;
    }

    private static string Tail(string s)
    {
        s = s.Trim();
        return s.Length <= 500 ? s : "..." + s[^500..];
    }
}
