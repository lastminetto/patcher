using System.Net;
using System.Net.Sockets;
using PvePatcher.Core;

namespace PvePatcher.Integrations.Proxmox;

public sealed class IpSelector : IIpSelector
{
    private static readonly string[] IgnoredPrefixes =
        ["docker", "veth", "br-", "virbr", "cni", "flannel", "cali", "tun", "tailscale", "wg", "zt", "kube", "vxlan"];

    public IPAddress? Select(DiscoveredVm vm, IpOverride? ipOverride, IReadOnlyList<IPNetwork> preferredNetworks)
    {
        switch (ipOverride?.Mode ?? IpOverrideMode.Auto)
        {
            case IpOverrideMode.Fixed:
                var text = ipOverride!.Value?.Trim();
                return !string.IsNullOrEmpty(text) && (text.Contains('.') || text.Contains(':')) && IPAddress.TryParse(text, out var ip)
                    ? ip : null;

            case IpOverrideMode.Nic:
                var nic = FindNic(vm, ipOverride!.Value);
                return nic is null ? null : Order(nic.Addresses, []).FirstOrDefault();

            default:
                var candidates = vm.Nics.Where(n => !IsIgnored(n.Name)).SelectMany(n => n.Addresses);
                return Order(candidates, preferredNetworks).FirstOrDefault();
        }
    }

    /// <summary>Descarta loopback/link-local/não especificado; IPv4 antes de IPv6; redes preferidas antes das demais.</summary>
    private static IEnumerable<IPAddress> Order(IEnumerable<IPAddress> addresses, IReadOnlyList<IPNetwork> preferred)
    {
        var usable = addresses.Where(IsUsable).ToList();
        return usable.Where(a => a.AddressFamily == AddressFamily.InterNetwork)
            .Concat(usable.Where(a => a.AddressFamily == AddressFamily.InterNetworkV6))
            .Select((a, i) => (a, i))
            .OrderBy(x => x.a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
            .ThenBy(x => preferred.Any(n => n.Contains(x.a)) ? 0 : 1)
            .ThenBy(x => x.i)
            .Select(x => x.a);
    }

    private static bool IsUsable(IPAddress a) =>
        !IPAddress.IsLoopback(a) && !a.Equals(IPAddress.Any) && !a.Equals(IPAddress.IPv6Any) &&
        !(a.AddressFamily == AddressFamily.InterNetworkV6 && (a.IsIPv6LinkLocal || a.IsIPv6Multicast)) &&
        !(a.AddressFamily == AddressFamily.InterNetwork && a.GetAddressBytes() is [169, 254, ..]);

    private static bool IsIgnored(string name) =>
        name.Equals("lo", StringComparison.OrdinalIgnoreCase) ||
        IgnoredPrefixes.Any(p => name.StartsWith(p, StringComparison.OrdinalIgnoreCase));

    private static GuestNic? FindNic(DiscoveredVm vm, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        var mac = NormalizeMac(value);
        return vm.Nics.FirstOrDefault(n => n.Mac is not null && mac.Length > 0 && NormalizeMac(n.Mac) == mac)
               ?? vm.Nics.FirstOrDefault(n => n.Name.Equals(value.Trim(), StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Hex sem separadores; vazio se não parecer um MAC de 12 dígitos.</summary>
    private static string NormalizeMac(string mac)
    {
        var hex = new string(mac.Where(c => c is not (':' or '-')).Select(char.ToLowerInvariant).ToArray());
        return hex.Length == 12 && hex.All(Uri.IsHexDigit) ? hex : "";
    }
}
