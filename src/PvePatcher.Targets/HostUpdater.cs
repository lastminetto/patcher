using Microsoft.Extensions.Options;
using PvePatcher.Core;

namespace PvePatcher.Targets;

public sealed class HostUpdater(IOptions<SshOptions> options) : IHostUpdater
{
    private readonly SshOptions _o = options.Value;

    public async Task<UpgradeOutcome> UpgradeAsync(ITargetSession session, UpgradeMode mode, IReadOnlyList<string> packages, Action<string>? onLine, CancellationToken ct)
    {
        if (mode == UpgradeMode.Packages && packages.Count == 0)
            throw new ArgumentException("Informe ao menos um pacote", nameof(packages));

        var timeout = TimeSpan.FromMinutes(_o.UpgradeTimeoutMinutes);
        var r = mode == UpgradeMode.All
            ? await session.RunAgentAsync("upgrade-all", [], onLine, timeout, ct).ConfigureAwait(false)
            : await session.RunAgentAsync("upgrade-pkgs", packages, onLine, timeout, ct).ConfigureAwait(false);

        var reboot = await RebootRequiredAsync(session, ct).ConfigureAwait(false);
        return new UpgradeOutcome(r.ExitCode == 0, r.ExitCode, reboot);
    }

    public async Task<bool> RebootRequiredAsync(ITargetSession session, CancellationToken ct)
    {
        var r = await session.RunAgentAsync("reboot-required", [], null, TimeSpan.FromSeconds(_o.QueryTimeoutSeconds), ct).ConfigureAwait(false);
        if (r.ExitCode != 0) throw new TargetException($"patcher-agent reboot-required falhou (exit {r.ExitCode}): {r.StdErr.Trim()}");
        return AgentOutputParser.ParseRebootRequired(r.StdOut);
    }

    public async Task RebootAsync(ITargetSession session, CancellationToken ct)
    {
        try
        {
            await session.RunAgentAsync("reboot", [], null, TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
        }
        catch (TargetException) { throw; }
        catch (Exception) when (!ct.IsCancellationRequested)
        {
            // a conexão pode cair antes de devolvermos o exit; o reboot já foi agendado
        }
    }
}
