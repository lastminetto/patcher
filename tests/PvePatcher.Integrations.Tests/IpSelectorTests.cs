using System.Net;
using PvePatcher.Core;
using PvePatcher.Integrations.Proxmox;

namespace PvePatcher.Integrations.Tests;

public class IpSelectorTests
{
    private readonly IpSelector _sel = new();

    private static GuestNic Nic(string name, string? mac, params string[] ips) =>
        new(name, mac, ips.Select(IPAddress.Parse).ToList());

    private static DiscoveredVm Vm(params GuestNic[] nics) =>
        new("c", "n", 1, "vm", "running", nics, null, true);

    private static readonly IReadOnlyList<IPNetwork> None = [];

    [Fact]
    public void Auto_SkipsNoiseAndPrefersIpv4()
    {
        var vm = Vm(
            Nic("lo", null, "127.0.0.1", "::1"),
            Nic("docker0", null, "172.17.0.1"),
            Nic("veth9", null, "10.9.9.9"),
            Nic("br-abc", null, "10.8.8.8"),
            Nic("tailscale0", null, "100.64.0.1"),
            Nic("eth0", null, "2001:db8::5", "169.254.1.1", "fe80::1", "172.22.10.5"));

        Assert.Equal(IPAddress.Parse("172.22.10.5"), _sel.Select(vm, null, None));
    }

    [Fact]
    public void Auto_FallsBackToGlobalIpv6()
    {
        var vm = Vm(Nic("eth0", null, "fe80::1", "2001:db8::5"));
        Assert.Equal(IPAddress.Parse("2001:db8::5"), _sel.Select(vm, null, None));
    }

    [Fact]
    public void Auto_PreferredNetworkWinsWithinFamily()
    {
        var vm = Vm(Nic("eth0", null, "10.0.0.5"), Nic("eth1", null, "172.22.10.5"));
        var pref = new[] { IPNetwork.Parse("172.22.0.0/16") };

        Assert.Equal(IPAddress.Parse("172.22.10.5"), _sel.Select(vm, null, pref));
        Assert.Equal(IPAddress.Parse("10.0.0.5"), _sel.Select(vm, null, None)); // ordem do agent
    }

    [Fact]
    public void Auto_PreferredIpv6DoesNotBeatIpv4()
    {
        var vm = Vm(Nic("eth0", null, "2001:db8::5", "10.0.0.5"));
        var pref = new[] { IPNetwork.Parse("2001:db8::/32") };
        Assert.Equal(IPAddress.Parse("10.0.0.5"), _sel.Select(vm, null, pref));
    }

    [Fact]
    public void Auto_NothingUsableReturnsNull()
    {
        Assert.Null(_sel.Select(Vm(Nic("lo", null, "127.0.0.1"), Nic("docker0", null, "172.17.0.1")), null, None));
        Assert.Null(_sel.Select(Vm(), new IpOverride(IpOverrideMode.Auto, null), None));
    }

    [Theory]
    [InlineData("BC:24:11:AA:BB:CC")]
    [InlineData("bc-24-11-aa-bb-cc")]
    [InlineData("eth1")]
    [InlineData("ETH1")]
    public void Nic_MatchesByMacOrName(string value)
    {
        var vm = Vm(Nic("eth0", "00:11:22:33:44:55", "10.0.0.5"), Nic("eth1", "bc:24:11:aa:bb:cc", "10.1.0.5"));
        Assert.Equal(IPAddress.Parse("10.1.0.5"), _sel.Select(vm, new IpOverride(IpOverrideMode.Nic, value), None));
    }

    [Fact]
    public void Nic_ExplicitChoiceIsNotFilteredByPrefix_ButSkipsLinkLocal()
    {
        var vm = Vm(Nic("docker0", null, "169.254.1.1", "172.17.0.1"));
        Assert.Equal(IPAddress.Parse("172.17.0.1"), _sel.Select(vm, new IpOverride(IpOverrideMode.Nic, "docker0"), None));
    }

    [Fact]
    public void Nic_Ipv4ThenGlobalIpv6_AndUnknownNicIsNull()
    {
        var vm = Vm(Nic("eth0", null, "fe80::1", "2001:db8::5"));
        Assert.Equal(IPAddress.Parse("2001:db8::5"), _sel.Select(vm, new IpOverride(IpOverrideMode.Nic, "eth0"), None));
        Assert.Null(_sel.Select(vm, new IpOverride(IpOverrideMode.Nic, "eth9"), None));
        Assert.Null(_sel.Select(vm, new IpOverride(IpOverrideMode.Nic, null), None));
    }

    [Theory]
    [InlineData("10.0.0.7", "10.0.0.7")]
    [InlineData(" 2001:db8::1 ", "2001:db8::1")]
    [InlineData("nao-eh-ip", null)]
    [InlineData("300.1.1.1", null)]
    [InlineData("7", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void Fixed_ParsesOrReturnsNull(string? value, string? expected)
    {
        var got = _sel.Select(Vm(), new IpOverride(IpOverrideMode.Fixed, value), None);
        Assert.Equal(expected is null ? null : IPAddress.Parse(expected), got);
    }
}
