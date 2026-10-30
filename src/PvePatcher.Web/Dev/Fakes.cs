using System.Collections.Concurrent;
using System.Net;
using PvePatcher.Core;

namespace PvePatcher.Web.Dev;

public sealed class FakeSecretStore : ISecretStore
{
    private readonly ConcurrentDictionary<string, IReadOnlyDictionary<string, string>> _data = new();

    public FakeSecretStore()
    {
        var kp = Ed25519OpenSsh.Generate("pve-patcher-dev");
        _data[SecretPaths.SshDefault] = new Dictionary<string, string>
        {
            [SecretPaths.PrivateKey] = kp.PrivateKey, [SecretPaths.PublicKey] = kp.PublicKey,
        };
        var console = Ed25519OpenSsh.Generate("pve-patcher-console-dev");
        _data[SecretPaths.SshConsole] = new Dictionary<string, string>
        {
            [SecretPaths.PrivateKey] = console.PrivateKey, [SecretPaths.PublicKey] = console.PublicKey,
        };
    }

    public Task<VaultStatus> GetStatusAsync(CancellationToken ct) => Task.FromResult(new VaultStatus(VaultState.Ready, "fake"));
    public Task<IReadOnlyDictionary<string, string>?> ReadAsync(string path, CancellationToken ct) =>
        Task.FromResult(_data.TryGetValue(path, out var d) ? d : null);
    public Task WriteAsync(string path, IReadOnlyDictionary<string, string> data, CancellationToken ct)
    {
        _data[path] = new Dictionary<string, string>(data);
        return Task.CompletedTask;
    }
    public Task DeleteAsync(string path, CancellationToken ct)
    {
        _data.TryRemove(path, out _);
        return Task.CompletedTask;
    }
}

public sealed class FakeProxmoxClient : IProxmoxClient, IProxmoxServicePermissions
{
    private readonly ConcurrentDictionary<int, List<VmSnapshot>> _snaps = new();

    public async Task<IReadOnlyList<DiscoveredVm>> DiscoverVmsAsync(ClusterConfig cluster, CancellationToken ct)
    {
        await Task.Delay(300, ct);
        return FakeWorld.Vms.Where(v => v.ClusterId == cluster.Id)
            .Select(v => new DiscoveredVm(v.ClusterId, v.Node, v.VmId, v.Name, v.Status,
                v.Agent ? FakeWorld.NicsOf(v) : [], v.Agent ? v.Os : null, v.Agent)).ToList();
    }

    public Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> GetServicePermissionsAsync(ClusterConfig cluster, CancellationToken ct) =>
        Task.FromResult<IReadOnlyDictionary<string, IReadOnlySet<string>>>(new Dictionary<string, IReadOnlySet<string>>
        {
            ["/"] = new HashSet<string> { "VM.Audit", "VM.GuestAgent.Audit", "VM.Monitor", "VM.Snapshot", "Sys.Audit" },
        });

    public Task<string?> LocateVmAsync(ClusterConfig cluster, int vmId, CancellationToken ct) =>
        Task.FromResult(FakeWorld.Vms.FirstOrDefault(v => v.ClusterId == cluster.Id && v.VmId == vmId)?.Node);

    public Task<IReadOnlyList<VmSnapshot>> ListSnapshotsAsync(ClusterConfig cluster, VmRef vm, CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<VmSnapshot>>(_snaps.GetOrAdd(vm.VmId, _ => [new VmSnapshot("patcher-20240101-0300", "antigo", DateTimeOffset.UtcNow.AddDays(-30))]).ToList());

    public async Task CreateSnapshotAsync(ClusterConfig cluster, VmRef vm, string name, string description, CancellationToken ct)
    {
        await Task.Delay(1500, ct);
        _snaps.GetOrAdd(vm.VmId, _ => []).Add(new VmSnapshot(name, description, DateTimeOffset.UtcNow));
    }

    public async Task DeleteSnapshotAsync(ClusterConfig cluster, VmRef vm, string name, CancellationToken ct)
    {
        await Task.Delay(500, ct);
        _snaps.GetOrAdd(vm.VmId, _ => []).RemoveAll(s => s.Name == name);
    }

    public async Task<bool> WaitForGuestAgentAsync(ClusterConfig cluster, VmRef vm, TimeSpan timeout, CancellationToken ct)
    {
        await Task.Delay(2000, ct);
        return true;
    }
}

/// <summary>Senha "dev" para qualquer usuário; "totp@pve" pede o código 123456; "viewer@pve" só enxerga.</summary>
public sealed class FakeProxmoxAuth : IProxmoxAuth
{
    public Task<PveLoginResult> LoginAsync(ClusterConfig cluster, string userId, string password, CancellationToken ct)
    {
        if (password != "dev") return Task.FromResult(new PveLoginResult(PveLoginStatus.Failed, null, null, null, "authentication failure"));
        var status = userId.StartsWith("totp@") ? PveLoginStatus.NeedTotp : PveLoginStatus.Success;
        return Task.FromResult(new PveLoginResult(status, userId, "ticket:" + userId, "csrf", null));
    }

    public Task<PveLoginResult> CompleteTotpAsync(ClusterConfig cluster, string userId, string partialTicket, string totpCode, CancellationToken ct) =>
        Task.FromResult(totpCode == "123456"
            ? new PveLoginResult(PveLoginStatus.Success, userId, "ticket:" + userId, "csrf", null)
            : new PveLoginResult(PveLoginStatus.Failed, null, null, null, "código TOTP inválido"));

    public Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> GetPermissionsAsync(ClusterConfig cluster, string ticket, CancellationToken ct)
    {
        var user = ticket.Replace("ticket:", "");
        IReadOnlySet<string> Set(params string[] p) => p.ToHashSet();
        var map = new Dictionary<string, IReadOnlySet<string>>();
        if (user.StartsWith("viewer@")) map["/"] = Set("Sys.Audit");
        else if (user.StartsWith("ops@"))
        {
            map["/"] = Set("Sys.Audit");
            map["/vms/101"] = Set("VM.PowerMgmt");
            map["/vms/102"] = Set("VM.PowerMgmt");
        }
        else map["/"] = Set("Sys.Audit", "Sys.Modify", "VM.PowerMgmt");
        return Task.FromResult<IReadOnlyDictionary<string, IReadOnlySet<string>>>(map);
    }
}

public sealed class FakeIpSelector : IIpSelector
{
    private static readonly string[] SkipPrefixes = ["lo", "docker", "veth", "br-", "virbr", "cni", "flannel", "cali", "tun"];

    public IPAddress? Select(DiscoveredVm vm, IpOverride? ipOverride, IReadOnlyList<IPNetwork> preferredNetworks)
    {
        if (ipOverride is { Mode: IpOverrideMode.Fixed }) return IPAddress.TryParse(ipOverride.Value, out var f) ? f : null;
        if (ipOverride is { Mode: IpOverrideMode.Nic })
        {
            var nic = vm.Nics.FirstOrDefault(n => string.Equals(n.Mac, ipOverride.Value, StringComparison.OrdinalIgnoreCase) || n.Name == ipOverride.Value);
            return nic?.Addresses.FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
        }
        var cands = vm.Nics.Where(n => !SkipPrefixes.Any(p => n.Name.StartsWith(p)))
            .SelectMany(n => n.Addresses).Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && !IPAddress.IsLoopback(a)).ToList();
        return cands.FirstOrDefault(a => preferredNetworks.Any(n => n.Contains(a))) ?? cands.FirstOrDefault();
    }
}

public sealed class FakeTargetConnector : ITargetConnector
{
    public async Task<ITargetSession> ConnectAsync(SshTarget target, CancellationToken ct)
    {
        await Task.Delay(400, ct);
        var key = FakeWorld.HostKeyOf(target.Host);
        if (target.KnownHostKeySha256 is not null && target.KnownHostKeySha256 != key)
            throw new HostKeyMismatchException(target.KnownHostKeySha256, key);
        return new FakeSession(target.Host, key);
    }
}

public sealed class FakeSession(string host, string key) : ITargetSession
{
    public string Host { get; } = host;
    public string HostKeySha256 { get; } = key;
    public Task<CommandResult> RunAgentAsync(string subcommand, IReadOnlyList<string> args, Action<string>? onLine, TimeSpan timeout, CancellationToken ct) =>
        Task.FromResult(new CommandResult(0, "", ""));
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

public sealed class FakeHostScanner(FakeWorld world) : IHostScanner
{
    public async Task<HostScan> ScanAsync(ITargetSession session, Action<string>? onLine, CancellationToken ct)
    {
        var host = ((FakeSession)session).Host;
        var vm = FakeWorld.ByIp(host)!;
        onLine?.Invoke("agent: refresh dos índices...");
        await Task.Delay(700, ct);
        onLine?.Invoke("agent: listando instalados e pendentes");
        await Task.Delay(500, ct);
        var installed = Enumerable.Range(0, 240).Select(i => new InstalledPackage($"pkg{i}", $"pkg{i}", "1.0", "1.0", "amd64")).ToList();
        var pending = world.Pending(host).ToList();
        installed.AddRange(pending.Select(p => new InstalledPackage(p.Name, p.SourceName, p.InstalledVersion, p.InstalledVersion, p.Arch)));
        return new HostScan(vm.Os!, vm.Os!.Family == OsFamily.Apk ? "6.6.51-0-lts" : "6.1.0-18-amd64", installed, pending, world.RebootPending(host), DateTimeOffset.UtcNow);
    }
}

public sealed class FakeHostUpdater(FakeWorld world) : IHostUpdater
{
    public async Task<UpgradeOutcome> UpgradeAsync(ITargetSession session, UpgradeMode mode, IReadOnlyList<string> packages, Action<string>? onLine, CancellationToken ct)
    {
        var host = ((FakeSession)session).Host;
        var todo = world.Pending(host).Where(p => !p.HeldBack && (mode == UpgradeMode.All || packages.Contains(p.Name))).ToList();
        onLine?.Invoke($"Lendo listas de pacotes... {todo.Count} pacote(s) a atualizar");
        foreach (var p in todo)
        {
            await Task.Delay(700, ct);
            onLine?.Invoke($"Baixando {p.Name} {p.CandidateVersion}");
            await Task.Delay(500, ct);
            onLine?.Invoke($"Configurando {p.Name} ({p.CandidateVersion}) ...");
        }
        world.Upgrade(host, mode == UpgradeMode.All ? null : packages.ToHashSet());
        onLine?.Invoke("Concluído.");
        return new UpgradeOutcome(true, 0, world.RebootPending(host));
    }

    public Task<bool> RebootRequiredAsync(ITargetSession session, CancellationToken ct) =>
        Task.FromResult(world.RebootPending(((FakeSession)session).Host));

    public async Task RebootAsync(ITargetSession session, CancellationToken ct)
    {
        await Task.Delay(300, ct);
        world.SetReboot(((FakeSession)session).Host, false);
    }
}

public sealed class FakeVulnMatcher : IVulnerabilityMatcher
{
    private sealed record Cve(string Id, string Group, double Cvss, bool Kev, double Epss, string Summary, string? Advisory);

    private static readonly Cve[] Known =
    [
        new("CVE-2023-4911", "libc", 7.8, true, 0.93, "glibc: buffer overflow no ld.so (Looney Tunables) permite escalada local.", null),
        new("CVE-2024-2961", "libc", 7.3, false, 0.21, "glibc: overflow em iconv para ISO-2022-CN-EXT.", null),
        new("CVE-2024-6387", "ssh", 8.1, false, 0.62, "OpenSSH: condição de corrida no sshd (regreSSHion), RCE não autenticada.", "DSA-5724-1"),
        new("CVE-2024-5535", "ssl", 9.1, false, 0.02, "OpenSSL: SSL_select_next_proto lê além do buffer.", null),
        new("CVE-2025-32463", "sudo", 9.3, true, 0.55, "sudo: escalada via --chroot.", null),
        new("CVE-2024-2398", "curl", 8.6, false, 0.10, "curl: vazamento de memória em push de HTTP/2.", null),
        new("CVE-2024-1086", "kernel", 7.8, true, 0.97, "kernel: use-after-free no nf_tables permite escalada local.", null),
        new("CVE-2021-4034", "polkit", 7.8, true, 0.96, "polkit pkexec: escalada local (PwnKit).", "ALSA-2022:0267"),
        new("CVE-2024-8096", "curl", 5.3, false, 0.01, "curl: validação OCSP incorreta.", null),
        new("CVE-2022-3715", "bash", 7.8, false, 0.01, "bash: heap overflow em valid_parameter_transform.", null),
        new("CVE-2024-7348", "tzdata", 3.9, false, 0.00, "dados de fuso: baixa severidade.", null),
    ];

    private static string? GroupOf(string pkg) => pkg switch
    {
        _ when pkg.StartsWith("libc6") || pkg is "glibc" || pkg is "musl" => "libc",
        _ when pkg.StartsWith("openssh") => "ssh",
        _ when pkg.StartsWith("libssl") || pkg.StartsWith("openssl") => "ssl",
        "sudo" => "sudo",
        "curl" => "curl",
        _ when pkg.StartsWith("linux-image") || pkg == "kernel" => "kernel",
        "polkit" => "polkit",
        "tzdata" => "tzdata",
        _ => null,
    };

    public Task<IReadOnlyList<CveFinding>> MatchAsync(HostScan scan, SeverityThresholds th, CancellationToken ct)
    {
        var list = new List<CveFinding>();
        foreach (var p in scan.Pending)
        {
            var g = GroupOf(p.Name);
            foreach (var c in Known.Where(c => c.Group == g))
            {
                var status = p.HeldBack ? FindingStatus.FixNotInCandidate : FindingStatus.FixedByPendingUpdate;
                list.Add(Make(c, p.Name, p.SourceName, p.InstalledVersion, p.CandidateVersion, status, th, scan.Os));
            }
        }
        // Um CVE sem correção publicada e outro cuja correção ainda não chegou ao repositório.
        var bash = scan.Installed.FirstOrDefault(i => i.Name == "bash") ?? scan.Installed.FirstOrDefault();
        if (bash is not null)
            list.Add(Make(Known.First(c => c.Group == "bash"), "bash", "bash", "5.2.15-2", null, FindingStatus.Unfixed, th, scan.Os));
        return Task.FromResult<IReadOnlyList<CveFinding>>(list);
    }

    private static CveFinding Make(Cve c, string pkg, string src, string inst, string? cand, FindingStatus st, SeverityThresholds th, OsInfo os)
    {
        var sev = c.Cvss >= th.CriticalCvss ? Severity.Critical
            : c.Cvss >= th.HighCvss || c.Epss >= th.HighEpss || c.Kev ? Severity.High
            : c.Cvss >= th.MediumCvss ? Severity.Medium : Severity.Low;
        return new CveFinding(c.Id, c.Advisory, pkg, src, inst, st == FindingStatus.Unfixed ? null : cand, cand, st, c.Cvss,
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", c.Kev, c.Epss, sev.ToString().ToLowerInvariant(), sev, c.Summary);
    }
}

public sealed class FakeFeedUpdater : IVulnFeedUpdater
{
    private DateTimeOffset _at = DateTimeOffset.UtcNow.AddHours(-3);

    public async Task UpdateAsync(IReadOnlyCollection<OsInfo> releasesInUse, CancellationToken ct)
    {
        await Task.Delay(1500, ct);
        _at = DateTimeOffset.UtcNow;
    }

    public Task EnrichAsync(IReadOnlyCollection<string> cveIds, Action<string>? log, CancellationToken ct) => Task.CompletedTask;

    public Task<IReadOnlyList<FeedState>> GetStatusAsync(CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<FeedState>>([
            new("OSV debian:12", _at, 4210, null), new("OSV ubuntu:24.04", _at, 3980, null),
            new("CISA KEV", _at, 1190, null), new("EPSS", _at, 250000, null),
            new("NVD", _at.AddHours(-1), 312, "rate limit atingido (HTTP 429); tentará de novo"),
        ]);
}
