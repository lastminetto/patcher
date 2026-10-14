using NSubstitute;
using PvePatcher.Core;
using PvePatcher.Web.Data;
using PvePatcher.Web.Jobs;

namespace PvePatcher.Web.Tests;

public class UpgradeOrchestratorTests
{
    private static readonly ClusterConfig Cluster = new("prod", "Prod", ["https://x:8006"], null);
    private static readonly VmKey Vm = new("prod", 101);

    private readonly IProxmoxClient _pve = Substitute.For<IProxmoxClient>();
    private readonly IVmSessionProvider _sessions = Substitute.For<IVmSessionProvider>();
    private readonly IHostUpdater _updater = Substitute.For<IHostUpdater>();
    private readonly IVmScanner _scanner = Substitute.For<IVmScanner>();
    private readonly ITargetSession _session = Substitute.For<ITargetSession>();
    private readonly List<string> _log = [];

    public UpgradeOrchestratorTests()
    {
        _pve.LocateVmAsync(Cluster, 101, Arg.Any<CancellationToken>()).Returns("pve2");
        _pve.WaitForGuestAgentAsync(default!, default!, default, default).ReturnsForAnyArgs(true);
        _pve.ListSnapshotsAsync(default!, default!, default).ReturnsForAnyArgs(Task.FromResult<IReadOnlyList<VmSnapshot>>([]));
        _sessions.OpenAsync(Vm, Arg.Any<Action<string>?>(), Arg.Any<CancellationToken>()).Returns(_session);
        _scanner.ScanAsync(Vm, Arg.Any<Action<string>>(), Arg.Any<CancellationToken>()).Returns(new ScanSummary(0, 0, false));
        _updater.UpgradeAsync(default!, default, default!, default, default)
            .ReturnsForAnyArgs(new UpgradeOutcome(true, 0, false));
    }

    private UpgradeOrchestrator Make() => new(_pve, _sessions, _updater, _scanner,
        new FixedTime(new DateTimeOffset(2026, 10, 14, 3, 5, 0, TimeSpan.Zero)),
        new UpgradeTimings(TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(10)),
        (_, _) => Task.CompletedTask);

    private UpgradeContext Ctx(bool snapshot = true, bool reboot = false, bool security = false, params string[] pkgs) =>
        new(Cluster, Vm, "pve1", "root@pam", new UpgradeOptions(snapshot, reboot, security), pkgs);

    [Fact]
    public async Task SnapshotFailure_AbortsBeforeUpgrade()
    {
        _pve.CreateSnapshotAsync(default!, default!, default!, default!, default)
            .ReturnsForAnyArgs(Task.FromException(new ProxmoxException("storage sem snapshot")));

        var ex = await Assert.ThrowsAsync<JobFailedException>(() => Make().RunAsync(Ctx(), _log.Add, default));

        Assert.Contains("snapshot", ex.Message, StringComparison.OrdinalIgnoreCase);
        await _updater.DidNotReceiveWithAnyArgs().UpgradeAsync(default!, default, default!, default, default);
        await _sessions.DidNotReceiveWithAnyArgs().OpenAsync(default, default, default);
    }

    [Fact]
    public async Task SecurityOnly_WithoutPackages_DoesNotRun()
    {
        await Assert.ThrowsAsync<JobFailedException>(() => Make().RunAsync(Ctx(security: true), _log.Add, default));

        await _pve.DidNotReceiveWithAnyArgs().CreateSnapshotAsync(default!, default!, default!, default!, default);
        await _updater.DidNotReceiveWithAnyArgs().UpgradeAsync(default!, default, default!, default, default);
    }

    [Fact]
    public async Task SecurityOnly_UpgradesOnlyListedPackages()
    {
        await Make().RunAsync(Ctx(false, false, true, "openssl", "libc6", "openssl"), _log.Add, default);

        await _updater.Received(1).UpgradeAsync(_session, UpgradeMode.Packages,
            Arg.Is<IReadOnlyList<string>>(l => l.SequenceEqual(new[] { "openssl", "libc6" })), Arg.Any<Action<string>?>(), Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(true, true, true)]
    [InlineData(true, false, false)]   // marcado, mas não exigido
    [InlineData(false, true, false)]   // exigido, mas não marcado
    [InlineData(false, false, false)]
    public async Task Reboot_OnlyWhenRequestedAndRequired(bool requested, bool required, bool expected)
    {
        _updater.UpgradeAsync(default!, default, default!, default, default)
            .ReturnsForAnyArgs(new UpgradeOutcome(true, 0, required));

        var r = await Make().RunAsync(Ctx(false, requested), _log.Add, default);

        Assert.Equal(expected, r.Rebooted);
        if (expected) await _updater.Received(1).RebootAsync(_session, Arg.Any<CancellationToken>());
        else await _updater.DidNotReceiveWithAnyArgs().RebootAsync(default!, default);
        await _scanner.Received(1).ScanAsync(Vm, Arg.Any<Action<string>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Snapshot_UsesLocatedNodeAndRemovesOldPatcherSnapshots()
    {
        _pve.ListSnapshotsAsync(default!, default!, default).ReturnsForAnyArgs(Task.FromResult<IReadOnlyList<VmSnapshot>>(
        [
            new VmSnapshot("patcher-20260101-0300", null, null),
            new VmSnapshot("patcher-20260901-0300", null, null),
            new VmSnapshot("patcher-20261014-0305", null, null),   // o recém-criado
            new VmSnapshot("antes-da-migracao", null, null),       // do usuário: não mexer
        ]));

        await Make().RunAsync(Ctx(), _log.Add, default);

        await _pve.Received(1).CreateSnapshotAsync(Cluster, Arg.Is<VmRef>(v => v.Node == "pve2"),
            "patcher-20261014-0305", Arg.Is<string>(d => d.Contains("root@pam")), Arg.Any<CancellationToken>());
        await _pve.Received(1).DeleteSnapshotAsync(Cluster, Arg.Any<VmRef>(), "patcher-20260101-0300", Arg.Any<CancellationToken>());
        await _pve.Received(1).DeleteSnapshotAsync(Cluster, Arg.Any<VmRef>(), "patcher-20260901-0300", Arg.Any<CancellationToken>());
        await _pve.DidNotReceive().DeleteSnapshotAsync(Cluster, Arg.Any<VmRef>(), "patcher-20261014-0305", Arg.Any<CancellationToken>());
        await _pve.DidNotReceive().DeleteSnapshotAsync(Cluster, Arg.Any<VmRef>(), "antes-da-migracao", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task FailedUpgrade_SkipsReboot_StillRescans_AndFails()
    {
        _updater.UpgradeAsync(default!, default, default!, default, default)
            .ReturnsForAnyArgs(new UpgradeOutcome(false, 100, true));

        await Assert.ThrowsAsync<JobFailedException>(() => Make().RunAsync(Ctx(false, true), _log.Add, default));

        await _updater.DidNotReceiveWithAnyArgs().RebootAsync(default!, default);
        await _scanner.Received(1).ScanAsync(Vm, Arg.Any<Action<string>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AfterReboot_RetriesSshUntilBack()
    {
        _updater.UpgradeAsync(default!, default, default!, default, default).ReturnsForAnyArgs(new UpgradeOutcome(true, 0, true));
        var calls = 0;
        _sessions.OpenAsync(Vm, Arg.Any<Action<string>?>(), Arg.Any<CancellationToken>())
            .Returns(_ => ++calls is 2 or 3 ? Task.FromException<ITargetSession>(new IOException("recusada")) : Task.FromResult(_session));

        var r = await Make().RunAsync(Ctx(false, true), _log.Add, default);

        Assert.True(r.Rebooted);
        Assert.True(calls >= 4);
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
