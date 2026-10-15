using System.Diagnostics;
using System.Net;
using System.Text.RegularExpressions;
using System.Text.Json;
using PvePatcher.Core;

namespace PvePatcher.Integrations.Proxmox;

public sealed class ProxmoxClientOptions
{
    /// <summary>Intervalo entre consultas do status de uma task.</summary>
    public TimeSpan TaskPollInterval { get; set; } = TimeSpan.FromSeconds(1);
    public TimeSpan TaskTimeout { get; set; } = TimeSpan.FromMinutes(10);
    /// <summary>Timeout das chamadas ao guest agent no discovery.</summary>
    public TimeSpan AgentTimeout { get; set; } = TimeSpan.FromSeconds(5);
    public int AgentParallelism { get; set; } = 8;
    /// <summary>Espera inicial do ping do agent (dobra até 10 s).</summary>
    public TimeSpan PingInitialDelay { get; set; } = TimeSpan.FromSeconds(1);
}

public sealed partial class ProxmoxClient(ISecretStore secrets, PveHttp http, ProxmoxClientOptions? options = null) : IProxmoxClient, IProxmoxServicePermissions
{
    private readonly ProxmoxClientOptions _opt = options ?? new();

    [GeneratedRegex("^[A-Za-z][A-Za-z0-9_-]{1,39}$")]
    private static partial Regex SnapshotNameRegex();

    public static bool IsValidSnapshotName(string name) => SnapshotNameRegex().IsMatch(name);

    public async Task<IReadOnlyList<DiscoveredVm>> DiscoverVmsAsync(ClusterConfig cluster, CancellationToken ct)
    {
        var data = await GetAsync(cluster, "/cluster/resources?type=vm", ct);
        var vms = new List<(string Node, int VmId, string Name, string Status)>();
        foreach (var r in Items(data))
        {
            if (Str(r, "type") != "qemu" || Int(r, "template") == 1)
                continue;
            if (Int(r, "vmid") is not { } vmid || Str(r, "node") is not { } node)
                continue;
            vms.Add((node, vmid, Str(r, "name") ?? $"vm{vmid}", Str(r, "status") ?? "unknown"));
        }

        var gate = new SemaphoreSlim(Math.Max(1, _opt.AgentParallelism));
        var tasks = vms.Select(async vm =>
        {
            if (vm.Status != "running")
                return new DiscoveredVm(cluster.Id, vm.Node, vm.VmId, vm.Name, vm.Status, [], null, false);

            await gate.WaitAsync(ct);
            try
            {
                var nics = QueryAgentAsync(cluster, vm.Node, vm.VmId, "network-get-interfaces", ParseNics, ct);
                var os = QueryAgentAsync(cluster, vm.Node, vm.VmId, "get-osinfo", ParseOs, ct);
                var nicsResult = await nics;
                var osResult = await os;
                return new DiscoveredVm(cluster.Id, vm.Node, vm.VmId, vm.Name, vm.Status,
                    nicsResult.Value ?? [], osResult.Value, nicsResult.Ok || osResult.Ok);
            }
            finally
            {
                gate.Release();
            }
        });
        return await Task.WhenAll(tasks);
    }

    public async Task<string?> LocateVmAsync(ClusterConfig cluster, int vmId, CancellationToken ct)
    {
        var data = await GetAsync(cluster, "/cluster/resources?type=vm", ct);
        return Items(data).Where(r => Str(r, "type") == "qemu" && Int(r, "vmid") == vmId)
            .Select(r => Str(r, "node")).FirstOrDefault();
    }

    public async Task<IReadOnlyList<VmSnapshot>> ListSnapshotsAsync(ClusterConfig cluster, VmRef vm, CancellationToken ct)
    {
        var data = await GetAsync(cluster, $"{VmPath(vm)}/snapshot", ct);
        return Items(data)
            .Where(s => Str(s, "name") is not (null or "current"))
            .Select(s => new VmSnapshot(
                Str(s, "name")!,
                Str(s, "description"),
                Int64(s, "snaptime") is { } t ? DateTimeOffset.FromUnixTimeSeconds(t) : null))
            .ToList();
    }

    public async Task CreateSnapshotAsync(ClusterConfig cluster, VmRef vm, string name, string description, CancellationToken ct)
    {
        if (!IsValidSnapshotName(name))
            throw new ArgumentException($"Nome de snapshot inválido: '{name}' (use letras, dígitos, _ e -, começando por letra, 2 a 40 caracteres).", nameof(name));

        var form = new Dictionary<string, string> { ["snapname"] = name, ["description"] = description, ["vmstate"] = "0" };
        var upid = await SendAsync(cluster, HttpMethod.Post, $"{VmPath(vm)}/snapshot", form, ct);
        await WaitForTaskAsync(cluster, vm.Node, upid, ct);
    }

    public async Task DeleteSnapshotAsync(ClusterConfig cluster, VmRef vm, string name, CancellationToken ct)
    {
        if (!IsValidSnapshotName(name))
            throw new ArgumentException($"Nome de snapshot inválido: '{name}'.", nameof(name));

        var upid = await SendAsync(cluster, HttpMethod.Delete, $"{VmPath(vm)}/snapshot/{name}", null, ct);
        await WaitForTaskAsync(cluster, vm.Node, upid, ct);
    }

    public async Task<bool> WaitForGuestAgentAsync(ClusterConfig cluster, VmRef vm, TimeSpan timeout, CancellationToken ct)
    {
        var clock = Stopwatch.StartNew();
        var delay = _opt.PingInitialDelay;
        while (true)
        {
            try
            {
                await SendAsync(cluster, HttpMethod.Post, $"{VmPath(vm)}/agent/ping", null, ct,
                    _opt.AgentTimeout, failoverOnTimeout: false);
                return true;
            }
            catch (ProxmoxException)
            {
                // agent ainda não respondeu (500 "not running") ou nó inacessível: tenta de novo
            }

            var remaining = timeout - clock.Elapsed;
            if (remaining <= TimeSpan.Zero)
                return false;
            await Task.Delay(delay < remaining ? delay : remaining, ct);
            delay = TimeSpan.FromTicks(Math.Min(delay.Ticks * 2, TimeSpan.FromSeconds(10).Ticks));
        }
    }

    public async Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> GetServicePermissionsAsync(ClusterConfig cluster, CancellationToken ct)
    {
        var data = await GetAsync(cluster, "/access/permissions", ct);
        var result = new Dictionary<string, IReadOnlySet<string>>();
        if (data.ValueKind != JsonValueKind.Object)
            return result; // token sem privilégios: o PVE devolve {} (ou null)
        foreach (var path in data.EnumerateObject())
            if (path.Value.ValueKind == JsonValueKind.Object)
                result[path.Name] = path.Value.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
        return result;
    }

    // ---- internos ----

    private static string VmPath(VmRef vm) => $"/nodes/{Uri.EscapeDataString(vm.Node)}/qemu/{vm.VmId}";

    private async Task<JsonElement> SendAsync(ClusterConfig cluster, HttpMethod method, string path,
        IReadOnlyDictionary<string, string>? form, CancellationToken ct, TimeSpan? timeout = null, bool failoverOnTimeout = true)
    {
        var secret = await secrets.ReadAsync(SecretPaths.Cluster(cluster.Id), ct);
        if (secret is null ||
            !secret.TryGetValue(SecretPaths.TokenId, out var id) ||
            !secret.TryGetValue(SecretPaths.TokenSecret, out var token))
            throw new ProxmoxException($"Token de serviço do cluster '{cluster.Id}' não cadastrado no cofre.");

        return await http.SendAsync(cluster, method, path, form,
            req => req.Headers.TryAddWithoutValidation("Authorization", $"PVEAPIToken={id}={token}"),
            ct, timeout, failoverOnTimeout);
    }

    private Task<JsonElement> GetAsync(ClusterConfig cluster, string path, CancellationToken ct) =>
        SendAsync(cluster, HttpMethod.Get, path, null, ct);

    /// <summary>Consulta ao guest agent; qualquer falha (agent mudo, VM sem agent, timeout) vira Ok=false.</summary>
    private async Task<(bool Ok, T? Value)> QueryAgentAsync<T>(ClusterConfig cluster, string node, int vmId, string command,
        Func<JsonElement, T?> parse, CancellationToken ct)
    {
        try
        {
            var data = await SendAsync(cluster, HttpMethod.Get, $"{VmPath(new VmRef(cluster.Id, node, vmId))}/agent/{command}",
                null, ct, _opt.AgentTimeout, failoverOnTimeout: false);
            return (true, parse(data));
        }
        catch (Exception e) when (e is ProxmoxException or JsonException or InvalidOperationException)
        {
            return (false, default);
        }
    }

    private static List<GuestNic> ParseNics(JsonElement data)
    {
        var nics = new List<GuestNic>();
        if (!data.TryGetProperty("result", out var result) || result.ValueKind != JsonValueKind.Array)
            return nics;
        foreach (var n in result.EnumerateArray())
        {
            var name = Str(n, "name");
            if (name is null or "lo")
                continue;
            var addrs = new List<IPAddress>();
            if (n.TryGetProperty("ip-addresses", out var ips) && ips.ValueKind == JsonValueKind.Array)
                foreach (var ip in ips.EnumerateArray())
                    if (Str(ip, "ip-address") is { } text && IPAddress.TryParse(text, out var parsed))
                        addrs.Add(parsed);
            nics.Add(new GuestNic(name, Str(n, "hardware-address"), addrs));
        }
        return nics;
    }

    private static OsInfo? ParseOs(JsonElement data)
    {
        if (!data.TryGetProperty("result", out var r) || r.ValueKind != JsonValueKind.Object)
            return null;
        var id = Str(r, "id");
        var pretty = Str(r, "pretty-name") ?? Str(r, "name") ?? id ?? "";
        return new OsInfo(OsInfo.ParseDistroId(id), Str(r, "version-id") ?? "", null, pretty);
    }

    private async Task WaitForTaskAsync(ClusterConfig cluster, string node, JsonElement upidEl, CancellationToken ct)
    {
        var upid = upidEl.ValueKind == JsonValueKind.String ? upidEl.GetString() : null;
        if (string.IsNullOrEmpty(upid))
            throw new ProxmoxException("O PVE não devolveu o UPID da task.");

        var taskPath = $"/nodes/{Uri.EscapeDataString(node)}/tasks/{Uri.EscapeDataString(upid)}";
        var clock = Stopwatch.StartNew();
        while (true)
        {
            var status = await GetAsync(cluster, $"{taskPath}/status", ct);
            if (Str(status, "status") == "stopped")
            {
                var exit = Str(status, "exitstatus") ?? "";
                if (exit == "OK")
                    return;
                throw new ProxmoxException($"Task do PVE falhou ({exit}){await LastLogLineAsync(cluster, taskPath, ct)}");
            }
            if (clock.Elapsed > _opt.TaskTimeout)
                throw new ProxmoxException($"Task do PVE não terminou em {_opt.TaskTimeout.TotalSeconds:0}s: {upid}");
            await Task.Delay(_opt.TaskPollInterval, ct);
        }
    }

    private async Task<string> LastLogLineAsync(ClusterConfig cluster, string taskPath, CancellationToken ct)
    {
        try
        {
            var log = await GetAsync(cluster, $"{taskPath}/log?start=0&limit=500", ct);
            var line = Items(log).Select(l => Str(l, "t")).LastOrDefault(t => !string.IsNullOrWhiteSpace(t));
            return line is null ? "" : $": {line}";
        }
        catch (ProxmoxException)
        {
            return "";
        }
    }

    private static IEnumerable<JsonElement> Items(JsonElement data) =>
        data.ValueKind == JsonValueKind.Array ? data.EnumerateArray() : [];

    internal static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v)
            ? v.ValueKind switch { JsonValueKind.String => v.GetString(), JsonValueKind.Number => v.GetRawText(), _ => null }
            : null;

    internal static int? Int(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v)
            ? v.ValueKind switch
            {
                JsonValueKind.Number when v.TryGetInt32(out var n) => n,
                JsonValueKind.String when int.TryParse(v.GetString(), out var n) => n,
                _ => null,
            }
            : null;

    private static long? Int64(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var n)
            ? n : null;
}
