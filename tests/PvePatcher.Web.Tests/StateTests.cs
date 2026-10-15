using System.Net;
using PvePatcher.Core;
using PvePatcher.Web.Auth;
using PvePatcher.Web.Data;
using PvePatcher.Web.Services;

namespace PvePatcher.Web.Tests;

public class PermissionTests
{
    private static PvePermissions P(params (string Path, string[] Privs)[] e) =>
        new(e.ToDictionary(x => x.Path, x => (IReadOnlySet<string>)x.Privs.ToHashSet()));

    [Fact]
    public void VmPermission_ChecksVmThenVmsThenRoot()
    {
        Assert.True(P(("/vms/101", ["VM.PowerMgmt"])).CanOperateVm(101));
        Assert.False(P(("/vms/101", ["VM.PowerMgmt"])).CanOperateVm(102));
        Assert.True(P(("/vms", ["VM.PowerMgmt"])).CanOperateVm(555));
        Assert.True(P(("/", ["VM.PowerMgmt"])).CanOperateVm(7));
        Assert.False(P(("/vms/101", ["VM.Audit"])).CanOperateVm(101));
        Assert.False(P().CanOperateVm(101));
    }

    [Fact]
    public void ViewAndAdmin_NeedRootPrivileges()
    {
        Assert.True(P(("/", ["Sys.Audit"])).CanView);
        Assert.False(P(("/vms", ["Sys.Audit"])).CanView);
        Assert.True(P(("/", ["Sys.Modify"])).CanAdmin);
        Assert.False(P(("/", ["Sys.Audit"])).CanAdmin);
    }

    [Fact]
    public void Claims_RoundTrip_AndOtherClusterIsReadOnly()
    {
        var user = new UserInfo("prod", "root@pam", P(("/", ["Sys.Audit", "VM.PowerMgmt"])));
        var back = UserInfo.FromPrincipal(user.ToPrincipal())!;
        Assert.Equal("prod", back.ClusterId);
        Assert.True(back.CanOperate("prod", 1));
        Assert.False(back.CanOperate("lab", 1));
    }
}

public class ReconcilerTests
{
    private static DiscoveredVm D(int id, string name, string node = "pve1", string status = "running", bool agent = true, string? ip = "10.0.0.1") =>
        new("prod", node, id, name, status, agent && ip is not null ? [new GuestNic("eth0", "AA:BB", [IPAddress.Parse(ip)])] : [],
            agent ? new OsInfo(Distro.Debian, "12", "bookworm", "Debian 12") : null, agent);

    [Fact]
    public void NewUpdatedAndRemoved()
    {
        var existing = new List<VmEntity>
        {
            new() { ClusterId = "prod", VmId = 1, Name = "a", Node = "pve1", Status = "running" },
            new() { ClusterId = "prod", VmId = 2, Name = "gone", Node = "pve1" },
        };

        var r = VmReconciler.Reconcile("prod", existing, [D(1, "a-renamed", node: "pve2"), D(3, "new")]);

        Assert.Equal([3], r.Added.Select(v => v.VmId));
        Assert.Equal([1], r.Updated.Select(v => v.VmId));
        Assert.Equal([2], r.Removed.Select(v => v.VmId));
        Assert.Equal("a-renamed", existing[0].Name);
        Assert.Equal("pve2", existing[0].Node);
        Assert.Equal("10.0.0.1", r.Added[0].Nics[0].Addresses[0].ToString());
        Assert.Equal(Distro.Debian, r.Added[0].Distro);
    }

    [Fact]
    public void AgentSilent_KeepsPreviousNicsAndOs()
    {
        var vm = VmReconciler.Reconcile("prod", [], [D(1, "a")]).Added[0];

        VmReconciler.Reconcile("prod", [vm], [D(1, "a", agent: false)]);

        Assert.False(vm.AgentResponding);
        Assert.Single(vm.Nics);
        Assert.NotNull(vm.Os);
    }
}

public class CountersTests
{
    private static CveFinding F(string cve, Severity sev, FindingStatus st, bool kev = false, string pkg = "p") =>
        new(cve, null, pkg, pkg, "1", "2", "2", st, null, null, kev, null, null, sev, null);

    [Fact]
    public void CountsDistinctFixableCvesBySeverity()
    {
        var c = VmCounters.Compute(
        [
            F("CVE-1", Severity.Critical, FindingStatus.FixedByPendingUpdate, kev: true, pkg: "a"),
            F("CVE-1", Severity.Critical, FindingStatus.FixedByPendingUpdate, kev: true, pkg: "b"), // mesmo CVE, outro binário
            F("CVE-2", Severity.High, FindingStatus.FixedByPendingUpdate),
            F("CVE-3", Severity.Medium, FindingStatus.FixNotInCandidate),
            F("CVE-4", Severity.High, FindingStatus.Unfixed),
            F("CVE-5", Severity.Low, FindingStatus.FixedByPendingUpdate),
        ], 7, 2);

        Assert.Equal(new VmCounters(7, 2, 1, 1, 0, 1, 1, 1), c);
    }

    [Fact]
    public void ApplyScan_StoresCountersAndState()
    {
        var os = new OsInfo(Distro.Debian, "12", "bookworm", "Debian 12");
        var scan = new HostScan(os, "6.1", [], [new PendingUpdate("a", "a", "1", "2", null, false), new PendingUpdate("b", "b", "1", "2", null, true)], true, DateTimeOffset.UtcNow);
        var vm = new VmEntity { ClusterId = "c", VmId = 1, State = ScanState.Error, LastError = "x" };

        vm.ApplyScan(scan, [F("CVE-1", Severity.High, FindingStatus.FixedByPendingUpdate, pkg: "a")]);

        Assert.Equal(2, vm.PendingCount);
        Assert.Equal(1, vm.HeldBackCount);
        Assert.Equal(1, vm.HighFixable);
        Assert.True(vm.RebootRequired);
        Assert.Equal(ScanState.Ok, vm.State);
        Assert.Null(vm.LastError);
        Assert.Single(vm.Findings);
        Assert.Equal(2, vm.Scan!.Pending.Count);
    }
}

public class Ed25519Tests
{
    [Fact]
    public void GeneratedKey_HasOpenSshShape()
    {
        var kp = Ed25519OpenSsh.Generate("t");
        Assert.StartsWith("-----BEGIN OPENSSH PRIVATE KEY-----\n", kp.PrivateKey);
        Assert.StartsWith("ssh-ed25519 AAAA", kp.PublicKey);
        Assert.EndsWith(" t", kp.PublicKey);
    }

    [Fact]
    public void GeneratedKey_IsAcceptedBySshKeygen()
    {
        var exe = new[] { "/usr/bin/ssh-keygen", @"C:\Windows\System32\OpenSSH\ssh-keygen.exe" }.FirstOrDefault(File.Exists);
        if (exe is null || OperatingSystem.IsWindows()) return; // ambiente sem OpenSSH: o teste de formato acima cobre o básico

        var kp = Ed25519OpenSsh.Generate("t");
        var file = Path.Combine(Path.GetTempPath(), "pvp-" + Guid.NewGuid().ToString("N"));
        try
        {
            File.WriteAllText(file, kp.PrivateKey); File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var psi = new System.Diagnostics.ProcessStartInfo(exe, $"-y -f \"{file}\"") { RedirectStandardOutput = true, RedirectStandardError = true };
            using var p = System.Diagnostics.Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEnd(); var err = p.StandardError.ReadToEnd();
            p.WaitForExit();
            Assert.True(p.ExitCode == 0, err);
            Assert.StartsWith(kp.PublicKey.Split(' ')[0] + " " + kp.PublicKey.Split(' ')[1], output);
        }
        finally { File.Delete(file); }
    }
}

public class ClusterTestDiagnosisTests
{
    private static DiscoveredVm Vm(string status = "running", bool agent = true) =>
        new("c", "n1", 100, "vm", status, [], null, agent);

    private static IReadOnlyDictionary<string, IReadOnlySet<string>> Perms(params string[] privs) =>
        privs.Length == 0
            ? new Dictionary<string, IReadOnlySet<string>>()
            : new Dictionary<string, IReadOnlySet<string>> { ["/"] = privs.ToHashSet() };

    [Fact]
    public void ZeroVms_EmptyAcl()
    {
        var r = ClusterTestDiagnosis.Evaluate([], Perms());
        Assert.True(r.Warning);
        Assert.Contains("Token sem permissões (ACL vazia)", r.Message);
        Assert.Contains("usuário E ao token", r.Message);
    }

    [Fact]
    public void ZeroVms_MissingVmAudit()
    {
        var r = ClusterTestDiagnosis.Evaluate([], Perms("Sys.Audit"));
        Assert.True(r.Warning);
        Assert.Contains("VM.Audit", r.Message);
    }

    [Fact]
    public void Vms_NoAgentResponding_MissingGuestAgentPrivs()
    {
        var r = ClusterTestDiagnosis.Evaluate([Vm(agent: false)], Perms("VM.Audit"));
        Assert.True(r.Warning);
        Assert.Contains("VM.GuestAgent.Audit", r.Message);
        Assert.Contains("VM.Monitor", r.Message);
    }

    [Fact]
    public void Vms_NoAgentResponding_PrivsPresent_MentionsGuestAgent()
    {
        var r = ClusterTestDiagnosis.Evaluate([Vm(agent: false)], Perms("VM.Audit", "VM.GuestAgent.Audit"));
        Assert.True(r.Warning);
        Assert.Contains("qemu-guest-agent", r.Message);
    }

    [Fact]
    public void AllStopped_NoWarning_AndHealthy_NoWarning()
    {
        Assert.False(ClusterTestDiagnosis.Evaluate([Vm("stopped", false)], null).Warning);
        var ok = ClusterTestDiagnosis.Evaluate([Vm()], null);
        Assert.False(ok.Warning);
        Assert.Contains("1 VM(s)", ok.Message);
    }
}
