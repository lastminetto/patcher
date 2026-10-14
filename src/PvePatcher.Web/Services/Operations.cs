using PvePatcher.Core;

namespace PvePatcher.Web.Services;

/// <summary>Ações do usuário (com checagem de permissão no servidor): enfileirar jobs, mexer em IP/host key.</summary>
public sealed class OperationsService(
    JobQueue queue, StateStore store, SettingsService settings, DiscoveryService discovery, VmIpService ips, AppEvents events)
{
    public static void Require(bool allowed, string what)
    {
        if (!allowed) throw new UnauthorizedAccessException($"Sem permissão: {what}.");
    }

    private static void RequireVm(UserInfo u, VmKey key) =>
        Require(u.CanOperate(key.ClusterId, key.VmId), "é preciso VM.PowerMgmt nesta VM (e estar logado no cluster dela)");

    public Job? EnqueueScan(UserInfo user, VmKey key, string? name = null, bool scheduled = false)
    {
        if (!scheduled) RequireVm(user, key);
        if (queue.FindActive(JobKind.Scan, key) is not null) return null;
        return queue.Enqueue(new Job { Kind = JobKind.Scan, Vm = key, Title = $"Scan {name ?? key.ToString()}", RequestedBy = user.UserId, Scheduled = scheduled });
    }

    /// <summary>Enfileira o scan das VMs ligadas que o usuário pode operar. Devolve (enfileiradas, ignoradas).</summary>
    public async Task<(int Queued, int Skipped)> EnqueueScanAllAsync(UserInfo user)
    {
        int q = 0, s = 0;
        foreach (var vm in (await store.GetVmsAsync()).Where(v => v.IsRunning).OrderBy(v => v.Name))
        {
            if (!user.CanOperate(vm.ClusterId, vm.VmId)) { s++; continue; }
            if (EnqueueScan(user, vm.Key, vm.Name) is not null) q++; else s++;
        }
        return (q, s);
    }

    public Job? EnqueueUpgrade(UserInfo user, VmKey key, string name, UpgradeOptions options)
    {
        RequireVm(user, key);
        if (queue.FindActive(JobKind.Upgrade, key) is not null) return null;
        return queue.Enqueue(new Job { Kind = JobKind.Upgrade, Vm = key, Title = $"Atualizar {name}", Upgrade = options, RequestedBy = user.UserId });
    }

    public Job? EnqueueFeedUpdate(UserInfo user, bool scheduled = false)
    {
        if (!scheduled) Require(user.CanAdmin, "é preciso Sys.Modify");
        if (queue.HasActiveFeedUpdate()) return null;
        return queue.Enqueue(new Job { Kind = JobKind.FeedUpdate, Title = "Atualizar base de CVEs", RequestedBy = user.UserId, Scheduled = scheduled });
    }

    public void Cancel(UserInfo user, Guid jobId)
    {
        var job = queue.Get(jobId);
        if (job is null) return;
        if (job.Vm is { } vm) RequireVm(user, vm); else Require(user.CanAdmin, "é preciso Sys.Modify");
        queue.Cancel(jobId);
    }

    public Task<DiscoveryReport> DiscoverNowAsync(UserInfo user, CancellationToken ct)
    {
        Require(user.Permissions.CanView, "é preciso Sys.Audit");
        return discovery.RunAsync(ct);
    }

    /// <summary>Muda a escolha de IP e a porta SSH; a mudança de rota invalida a host key conhecida? Não: só o usuário decide.</summary>
    public async Task SetNetworkAsync(UserInfo user, VmKey key, IpOverrideMode mode, string? value, int port)
    {
        RequireVm(user, key);
        if (port is < 1 or > 65535) throw new ArgumentException("Porta SSH inválida.");
        if (mode == IpOverrideMode.Fixed && !System.Net.IPAddress.TryParse(value?.Trim(), out _))
            throw new ArgumentException("IP manual inválido.");
        if (mode == IpOverrideMode.Nic && string.IsNullOrWhiteSpace(value))
            throw new ArgumentException("Escolha uma NIC.");
        await store.UpdateVmAsync(key, v =>
        {
            v.IpOverrideMode = mode;
            v.IpOverrideValue = mode == IpOverrideMode.Auto ? null : value!.Trim();
            v.SshPort = port;
        });
    }

    /// <summary>Aceita a host key pendente (só quem tem VM.PowerMgmt).</summary>
    public async Task AcceptHostKeyAsync(UserInfo user, VmKey key)
    {
        RequireVm(user, key);
        await store.UpdateVmAsync(key, v =>
        {
            if (v.PendingHostKey is null) return;
            v.KnownHostKey = v.PendingHostKey;
            v.PendingHostKey = null;
            v.State = ScanState.None;
            v.LastError = null;
        });
    }

    public AppSettings Settings => settings.Current;

    public string? EffectiveIp(VmEntity vm) => ips.Resolve(vm)?.ToString();

    public void Notify() => events.RaiseData();
}
