using PvePatcher.Core;

namespace PvePatcher.Web.Jobs;

/// <summary>Despacha cada tipo de job; aqui ficam as ligações com banco e cofre.</summary>
public sealed class JobExecutor(
    StateStore store, IVmScanner scanner, IVulnFeedUpdater feeds, IProxmoxClient pve, IHostUpdater updater,
    IVmSessionProvider sessions, VaultMonitor vault, TimeProvider time) : IJobExecutor
{
    public async Task<string?> ExecuteAsync(Job job, CancellationToken ct)
    {
        await vault.EnsureReadyAsync(ct);
        switch (job.Kind)
        {
            case JobKind.Scan:
            {
                var s = await scanner.ScanAsync(job.Vm!.Value, job.Log, ct);
                return $"{s.Pending} pendente(s), {s.FixableCves} CVE(s) corrigível(is){(s.RebootRequired ? ", reboot pendente" : "")}";
            }
            case JobKind.Upgrade:
                return await UpgradeAsync(job, ct);
            case JobKind.FeedUpdate:
            {
                var releases = (await store.GetVmsAsync()).Select(v => v.Os).OfType<OsInfo>()
                    .DistinctBy(o => (o.Distro, o.VersionId)).ToList();
                job.Log($"Atualizando feeds para {releases.Count} release(s) em uso...");
                await feeds.UpdateAsync(releases, ct);
                foreach (var f in await feeds.GetStatusAsync(ct))
                    job.Log($"{f.Name}: {f.Records} registro(s){(f.LastError is null ? "" : " — erro: " + f.LastError)}");
                return "Base de CVEs atualizada";
            }
            default:
                throw new InvalidOperationException(job.Kind.ToString());
        }
    }

    private async Task<string?> UpgradeAsync(Job job, CancellationToken ct)
    {
        var key = job.Vm!.Value;
        var vm = await store.GetVmAsync(key) ?? throw new JobFailedException("VM não encontrada.");
        var cluster = (await store.GetClusterAsync(key.ClusterId))?.ToConfig() ?? throw new JobFailedException("Cluster não encontrado.");
        // Leva todos os binários pendentes do mesmo pacote-fonte (ex.: openssl + libssl3), senão o upgrade
        // de um só deixa os irmãos na versão vulnerável ou quebra dependências de versão exata.
        var fixable = vm.Findings.Where(f => f.Status == FindingStatus.FixedByPendingUpdate).ToList();
        var fixableSources = fixable.Select(f => f.SourcePackage).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var sec = fixable.Select(f => f.Package)
            .Concat((vm.Scan?.Pending ?? []).Where(p => fixableSources.Contains(p.SourceName)).Select(p => p.Name))
            .Distinct(StringComparer.Ordinal).ToList();
        var orchestrator = new UpgradeOrchestrator(pve, sessions, updater, scanner, time, UpgradeTimings.Default);
        var r = await orchestrator.RunAsync(new UpgradeContext(cluster, key, vm.Node, job.RequestedBy, job.Upgrade!, sec), job.Log, ct);
        return r.Message;
    }

    public async Task OnFinishedAsync(Job job)
    {
        if (job.Vm is not { } key) return;
        var text = job.Text();
        if (text.Length > 200_000) text = "[...truncado...]\n" + text[^200_000..];
        await store.UpdateVmAsync(key, v =>
        {
            v.LastJobLog = text;
            v.LastJobAt = job.FinishedAt;
            v.LastJobKind = job.Kind == JobKind.Upgrade ? "Atualização" : "Scan";
            v.LastJobResult = $"{(job.Status == JobStatus.Succeeded ? "Sucesso" : job.Status == JobStatus.Cancelled ? "Cancelado" : "Falha")}: {job.Message}";
        });
    }
}
