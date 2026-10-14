using System.Collections.Concurrent;
using System.Net;
using PvePatcher.Core;

namespace PvePatcher.Web.Dev;

/// <summary>Estado simulado (clusters, VMs, pacotes pendentes) usado só com Dev:UseFakes=true.</summary>
public sealed class FakeWorld
{
    public sealed record FakeVm(string ClusterId, string Node, int VmId, string Name, string Status, OsInfo? Os, bool Agent, string[] Ips, string[]? Extra = null);

    public static readonly OsInfo Deb12 = new(Distro.Debian, "12", "bookworm", "Debian GNU/Linux 12 (bookworm)");
    public static readonly OsInfo Deb13 = new(Distro.Debian, "13", "trixie", "Debian GNU/Linux 13 (trixie)");
    public static readonly OsInfo Ubu24 = new(Distro.Ubuntu, "24.04", "noble", "Ubuntu 24.04.1 LTS");
    public static readonly OsInfo Ubu22 = new(Distro.Ubuntu, "22.04", "jammy", "Ubuntu 22.04.4 LTS");
    public static readonly OsInfo Alma9 = new(Distro.AlmaLinux, "9.4", null, "AlmaLinux 9.4 (Seafoam Ocelot)");
    public static readonly OsInfo Rocky9 = new(Distro.Rocky, "9.3", null, "Rocky Linux 9.3 (Blue Onyx)");
    public static readonly OsInfo Alp320 = new(Distro.Alpine, "3.20.3", null, "Alpine Linux v3.20");

    public static readonly FakeVm[] Vms =
    [
        new("prod", "pve1", 101, "web-01", "running", Deb12, true, ["10.10.1.11"]),
        new("prod", "pve1", 102, "db-01", "running", Ubu24, true, ["10.10.1.12"]),
        new("prod", "pve2", 103, "gateway-01", "running", Alma9, true, ["10.10.1.13", "192.168.50.13", "172.17.0.1"]),
        new("prod", "pve2", 104, "mon-01", "running", Alp320, true, ["10.10.1.14"]),
        new("prod", "pve2", 105, "legado-app", "running", null, false, []),
        new("lab", "lab1", 201, "lab-ubuntu", "running", Ubu22, true, ["10.20.0.21"]),
        new("lab", "lab1", 202, "lab-rocky", "running", Rocky9, true, ["10.20.0.22"]),
        new("lab", "lab2", 203, "lab-debian13", "stopped", Deb13, false, []),
    ];

    private readonly ConcurrentDictionary<string, List<PendingUpdate>> _pending = new();
    private readonly ConcurrentDictionary<string, bool> _reboot = new();

    public static IReadOnlyList<GuestNic> NicsOf(FakeVm vm)
    {
        var names = new[] { "eth0", "ens19", "docker0" };
        return vm.Ips.Select((ip, i) => new GuestNic(
            names[i], $"BC:24:11:{vm.VmId % 256:X2}:00:{i:X2}", [IPAddress.Parse(ip)])).ToList();
    }

    public static FakeVm? ByIp(string ip) => Vms.FirstOrDefault(v => v.Ips.Contains(ip));

    public List<PendingUpdate> Pending(string ip) => _pending.GetOrAdd(ip, _ => Initial(ByIp(ip)));

    public bool RebootPending(string ip) => _reboot.GetOrAdd(ip, _ => ip == "10.10.1.11");

    public void SetReboot(string ip, bool v) => _reboot[ip] = v;

    public void Upgrade(string ip, IReadOnlyCollection<string>? only)
    {
        var list = Pending(ip);
        var done = list.Where(p => !p.HeldBack && (only is null || only.Contains(p.Name))).ToList();
        list.RemoveAll(done.Contains);
        if (done.Any(p => p.Name.StartsWith("linux-image") || p.Name == "kernel" || p.Name is "libc6" or "glibc"))
            SetReboot(ip, true);
    }

    private static List<PendingUpdate> Initial(FakeVm? vm)
    {
        if (vm?.Os is null) return [];
        PendingUpdate P(string n, string a, string b, bool held = false, string? src = null) => new(n, src ?? n, a, b, "amd64", held);
        return vm.Os.Distro switch
        {
            Distro.Debian => [
                P("libc6", "2.36-9+deb12u3", "2.36-9+deb12u9", src: "glibc"),
                P("openssh-server", "1:9.2p1-2+deb12u1", "1:9.2p1-2+deb12u3", src: "openssh"),
                P("openssh-client", "1:9.2p1-2+deb12u1", "1:9.2p1-2+deb12u3", src: "openssh"),
                P("libssl3", "3.0.11-1~deb12u2", "3.0.15-1~deb12u1", src: "openssl"),
                P("linux-image-6.1.0-18-amd64", "6.1.76-1", "6.1.106-3", src: "linux"),
                P("curl", "7.88.1-10+deb12u5", "7.88.1-10+deb12u8"),
                P("tzdata", "2024a-0+deb12u1", "2024b-0+deb12u1"),
                P("libpam-systemd", "252.19-1~deb12u1", "252.26-1~deb12u2", held: true, src: "systemd"),
            ],
            Distro.Ubuntu => [
                P("libc6", "2.39-0ubuntu8.1", "2.39-0ubuntu8.3", src: "glibc"),
                P("openssh-server", "1:9.6p1-3ubuntu13", "1:9.6p1-3ubuntu13.5", src: "openssh"),
                P("sudo", "1.9.15p5-3ubuntu5", "1.9.15p5-3ubuntu5.24.04.1"),
                P("linux-image-6.8.0-45-generic", "6.8.0-45.45", "6.8.0-48.48", src: "linux"),
                P("libssl3t64", "3.0.13-0ubuntu3.1", "3.0.13-0ubuntu3.4", src: "openssl"),
                P("vim-tiny", "2:9.1.0016-1ubuntu7", "2:9.1.0016-1ubuntu7.3", src: "vim"),
            ],
            Distro.AlmaLinux or Distro.Rocky => [
                P("kernel", "5.14.0-362.8.1.el9_3", "5.14.0-427.35.1.el9_4"),
                P("glibc", "2.34-83.el9", "2.34-100.el9_4.4"),
                P("openssh-server", "8.7p1-34.el9", "8.7p1-38.el9_4.4", src: "openssh"),
                P("polkit", "0.117-11.el9", "0.117-12.el9", held: false),
                P("openssl-libs", "3.0.7-25.el9_3", "3.0.7-28.el9_4", src: "openssl"),
            ],
            Distro.Alpine => [
                P("openssl", "3.3.1-r3", "3.3.2-r0"),
                P("musl", "1.2.5-r0", "1.2.5-r1"),
                P("busybox", "1.36.1-r29", "1.36.1-r31"),
            ],
            _ => [],
        };
    }

    public static string HostKeyOf(string ip) =>
        "SHA256:" + Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("hostkey:" + ip))).TrimEnd('=');
}
