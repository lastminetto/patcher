using Microsoft.EntityFrameworkCore;
using PvePatcher.Core;

namespace PvePatcher.Web.Services;

public sealed record DiscoveryReport(int Added, int Updated, int Removed, Dictionary<string, string> Errors);

/// <summary>Discovery de VMs de todos os clusters; falha num cluster não afeta os demais.</summary>
public sealed class DiscoveryService(
    IDbContextFactory<AppDb> factory, IProxmoxClient pve, IProxmoxServicePermissions servicePerms, AppEvents events, ILogger<DiscoveryService> log)
{
    private readonly SemaphoreSlim _gate = new(1, 1);

    public bool Running => _gate.CurrentCount == 0;

    public async Task<DiscoveryReport> RunAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            int added = 0, updated = 0, removed = 0;
            var errors = new Dictionary<string, string>();
            List<ClusterEntity> clusters;
            await using (var db = await factory.CreateDbContextAsync(ct))
                clusters = await db.Clusters.AsNoTracking().ToListAsync(ct);

            foreach (var cluster in clusters)
            {
                try
                {
                    var found = await pve.DiscoverVmsAsync(cluster.ToConfig(), ct);
                    var r = await ApplyAsync(cluster.Id, found, ct);
                    added += r.Added.Count; updated += r.Updated.Count; removed += r.Removed.Count;
                    await SetClusterResultAsync(cluster.Id, null, ct);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    var msg = ex is VaultUnavailableException ? VaultMessages.Sealed : ex.Message;
                    log.LogWarning(ex, "Discovery do cluster {Cluster} falhou", cluster.Id);
                    errors[cluster.Id] = msg;
                    await SetClusterResultAsync(cluster.Id, msg, ct);
                }
            }
            events.RaiseData();
            return new DiscoveryReport(added, updated, removed, errors);
        }
        finally { _gate.Release(); }
    }

    /// <summary>Aplica o resultado do discovery de um cluster ao banco.</summary>
    public async Task<ReconcileResult> ApplyAsync(string clusterId, IReadOnlyList<DiscoveredVm> found, CancellationToken ct)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var existing = await db.Vms.Where(v => v.ClusterId == clusterId).ToListAsync(ct);
        var r = VmReconciler.Reconcile(clusterId, existing, found);
        db.Vms.AddRange(r.Added);
        db.Vms.RemoveRange(r.Removed);
        await db.SaveChangesAsync(ct);
        return r;
    }

    /// <summary>Dry-run para o botão "testar conexão", já com o diagnóstico de permissões do token de serviço.</summary>
    public async Task<ClusterTestResult> TestAsync(ClusterConfig cluster, CancellationToken ct)
    {
        var vms = await pve.DiscoverVmsAsync(cluster, ct);
        IReadOnlyDictionary<string, IReadOnlySet<string>>? perms = null;
        var needPerms = vms.Count == 0 || (vms.Any(v => v.Status == "running") && !vms.Any(v => v.AgentResponding));
        if (needPerms)
        {
            try { perms = await servicePerms.GetServicePermissionsAsync(cluster, ct); }
            catch (Exception ex) when (ex is ProxmoxException) { /* diagnóstico é best-effort */ }
        }
        return ClusterTestDiagnosis.Evaluate(vms, perms);
    }

    private async Task SetClusterResultAsync(string clusterId, string? error, CancellationToken ct)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var c = await db.Clusters.FindAsync([clusterId], ct);
        if (c is null) return;
        c.LastDiscoveryAt = DateTimeOffset.UtcNow;
        c.LastDiscoveryError = error;
        await db.SaveChangesAsync(ct);
    }
}

public sealed class DiscoveryBackgroundService(DiscoveryService discovery, SettingsService settings, ILogger<DiscoveryBackgroundService> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try { await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken); } catch (OperationCanceledException) { return; }
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await discovery.RunAsync(stoppingToken); }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { log.LogError(ex, "Discovery periódico falhou"); }
            try { await Task.Delay(TimeSpan.FromMinutes(Math.Clamp(settings.Current.DiscoveryMinutes, 1, 1440)), stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }
}
