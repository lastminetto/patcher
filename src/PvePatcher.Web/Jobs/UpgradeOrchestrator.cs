using PvePatcher.Core;

namespace PvePatcher.Web.Jobs;

/// <summary>Abre a sessão SSH de uma VM (chave do cofre, TOFU e bloqueio por host key divergente).</summary>
public interface IVmSessionProvider
{
    Task<ITargetSession> OpenAsync(VmKey vm, Action<string>? log, CancellationToken ct);
}

public sealed record ScanSummary(int Pending, int FixableCves, bool RebootRequired);

public interface IVmScanner
{
    /// <summary>Conecta, escaneia, cruza com CVEs e grava o estado da VM.</summary>
    Task<ScanSummary> ScanAsync(VmKey vm, Action<string> log, CancellationToken ct);
}

/// <param name="Node">Nó conhecido no discovery; o orquestrador reconfirma com LocateVmAsync.</param>
/// <param name="SecurityPackages">Binários com finding FixedByPendingUpdate (usado quando SecurityOnly).</param>
public sealed record UpgradeContext(
    ClusterConfig Cluster, VmKey Vm, string Node, string RequestedBy, UpgradeOptions Options, IReadOnlyList<string> SecurityPackages);

public sealed record UpgradeResult(bool Rebooted, string Message);

public sealed record UpgradeTimings(TimeSpan AgentWait, TimeSpan ReconnectWindow, TimeSpan ReconnectDelay)
{
    public static readonly UpgradeTimings Default = new(TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(3), TimeSpan.FromSeconds(10));
}

/// <summary>Sequência do upgrade de uma VM: snapshot, upgrade, reboot opcional e re-scan.</summary>
public sealed class UpgradeOrchestrator(
    IProxmoxClient pve,
    IVmSessionProvider sessions,
    IHostUpdater updater,
    IVmScanner scanner,
    TimeProvider time,
    UpgradeTimings timings,
    Func<TimeSpan, CancellationToken, Task>? delay = null)
{
    public const string SnapshotPrefix = "patcher-";

    private readonly Func<TimeSpan, CancellationToken, Task> _delay = delay ?? Task.Delay;

    public async Task<UpgradeResult> RunAsync(UpgradeContext c, Action<string> log, CancellationToken ct)
    {
        var opts = c.Options;
        IReadOnlyList<string> packages = [];
        if (opts.SecurityOnly)
        {
            packages = c.SecurityPackages.Distinct().ToList();
            if (packages.Count == 0)
                throw new JobFailedException("Nenhum pacote pendente corrige CVE: nada a atualizar no modo \"só segurança\".");
        }

        var vmRef = new VmRef(c.Cluster.Id, c.Node, c.Vm.VmId);
        if (opts.Snapshot)
            vmRef = await SnapshotAsync(c, packages, log, ct);

        log("== Atualizando pacotes ==");
        UpgradeOutcome outcome;
        var session = await sessions.OpenAsync(c.Vm, log, ct);
        var sessionOpen = true;
        try
        {
            outcome = await updater.UpgradeAsync(session, opts.SecurityOnly ? UpgradeMode.Packages : UpgradeMode.All, packages, log, ct);
            log(outcome.Success
                ? $"Upgrade concluído (reboot necessário: {(outcome.RebootRequired ? "sim" : "não")})."
                : $"Upgrade falhou (exit {outcome.ExitCode}).");

            var rebooted = false;
            if (outcome.Success && opts.Reboot && outcome.RebootRequired)
            {
                log("== Reiniciando a VM ==");
                await updater.RebootAsync(session, ct);
                await session.DisposeAsync();
                sessionOpen = false;
                await WaitForBackAsync(c, vmRef, log, ct);
                rebooted = true;
            }
            else if (outcome.Success && outcome.RebootRequired)
            {
                log("Reboot necessário, mas não solicitado; a VM segue pendente de reinício.");
            }

            if (sessionOpen) { await session.DisposeAsync(); sessionOpen = false; }

            log("== Re-scan ==");
            var summary = await scanner.ScanAsync(c.Vm, log, ct);

            if (!outcome.Success)
                throw new JobFailedException($"O upgrade terminou com erro (exit {outcome.ExitCode}); veja o log.");
            return new UpgradeResult(rebooted,
                $"Atualizada{(rebooted ? " e reiniciada" : "")}; restam {summary.Pending} pendente(s)" +
                (summary.RebootRequired ? ", reboot pendente." : "."));
        }
        finally
        {
            if (sessionOpen) await session.DisposeAsync();
        }
    }

    private async Task<VmRef> SnapshotAsync(UpgradeContext c, IReadOnlyList<string> packages, Action<string> log, CancellationToken ct)
    {
        log("== Snapshot ==");
        var node = await pve.LocateVmAsync(c.Cluster, c.Vm.VmId, ct)
            ?? throw new JobFailedException("A VM não foi encontrada no cluster; upgrade abortado.");
        var vmRef = new VmRef(c.Cluster.Id, node, c.Vm.VmId);
        var name = SnapshotPrefix + time.GetUtcNow().ToString("yyyyMMdd-HHmm");
        var pkgText = packages.Count > 0 ? "pacotes: " + string.Join(' ', packages) : "todos os pacotes";
        var desc = Truncate($"pve-patcher por {c.RequestedBy}; {pkgText}", 250);
        try
        {
            await pve.CreateSnapshotAsync(c.Cluster, vmRef, name, desc, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new JobFailedException($"Falha ao criar o snapshot ({ex.Message}); upgrade abortado, nada foi alterado na VM.", ex);
        }
        log($"Snapshot {name} criado.");

        try
        {
            foreach (var old in (await pve.ListSnapshotsAsync(c.Cluster, vmRef, ct))
                         .Where(s => s.Name.StartsWith(SnapshotPrefix, StringComparison.Ordinal) && s.Name != name))
            {
                await pve.DeleteSnapshotAsync(c.Cluster, vmRef, old.Name, ct);
                log($"Snapshot antigo {old.Name} removido.");
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log($"Aviso: não foi possível limpar snapshots antigos ({ex.Message}).");
        }
        return vmRef;
    }

    private async Task WaitForBackAsync(UpgradeContext c, VmRef vmRef, Action<string> log, CancellationToken ct)
    {
        // A VM pode ter migrado (HA) durante o reboot.
        var node = await pve.LocateVmAsync(c.Cluster, c.Vm.VmId, ct) ?? vmRef.Node;
        log($"Aguardando o guest agent (até {timings.AgentWait.TotalMinutes:0} min)...");
        if (!await pve.WaitForGuestAgentAsync(c.Cluster, vmRef with { Node = node }, timings.AgentWait, ct))
            throw new JobFailedException("A VM não voltou (guest agent sem resposta) após o reboot.");

        var attempts = Math.Max(1, (int)Math.Ceiling(timings.ReconnectWindow / timings.ReconnectDelay));
        Exception? last = null;
        for (var i = 1; i <= attempts; i++)
        {
            try
            {
                await using var s = await sessions.OpenAsync(c.Vm, null, ct);
                log("SSH respondendo após o reboot.");
                return;
            }
            catch (Exception ex) when (ex is not OperationCanceledException and not HostKeyBlockedException)
            {
                last = ex;
                log($"SSH ainda indisponível ({i}/{attempts}): {ex.Message}");
                await _delay(timings.ReconnectDelay, ct);
            }
        }
        throw new JobFailedException($"SSH não voltou após o reboot: {last?.Message}", last);
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];
}
