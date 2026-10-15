using System.Net;

namespace PvePatcher.Core;

/// <summary>Um cluster Proxmox cadastrado.</summary>
/// <param name="Id">Slug estável (usado no caminho do segredo e nas chaves do banco).</param>
/// <param name="Endpoints">URLs base de nós, ex.: "https://172.22.1.10:8006". Tentadas em ordem (failover).</param>
/// <param name="CertFingerprintSha256">
/// Impressão SHA-256 do certificado do pveproxy ("AA:BB:..."). Null = validar pela cadeia do sistema.
/// </param>
public sealed record ClusterConfig(string Id, string Name, IReadOnlyList<string> Endpoints, string? CertFingerprintSha256);

public sealed record GuestNic(string Name, string? Mac, IReadOnlyList<IPAddress> Addresses);

/// <summary>VM QEMU vista pela API. Nics e Os vêm do guest agent e ficam vazios/null se ele não responder.</summary>
public sealed record DiscoveredVm(
    string ClusterId,
    string Node,
    int VmId,
    string Name,
    string Status,
    IReadOnlyList<GuestNic> Nics,
    OsInfo? Os,
    bool AgentResponding);

public sealed record VmRef(string ClusterId, string Node, int VmId);

public sealed record VmSnapshot(string Name, string? Description, DateTimeOffset? Created);

/// <summary>Acesso à API do PVE com o token de serviço (lido do cofre).</summary>
public interface IProxmoxClient
{
    /// <summary>Todas as VMs QEMU não-template do cluster, com NICs/OS do guest agent para as que estão rodando.</summary>
    Task<IReadOnlyList<DiscoveredVm>> DiscoverVmsAsync(ClusterConfig cluster, CancellationToken ct);

    /// <summary>Nó atual da VM (pode ter migrado desde o discovery). Null se a VM não existe mais.</summary>
    Task<string?> LocateVmAsync(ClusterConfig cluster, int vmId, CancellationToken ct);

    Task<IReadOnlyList<VmSnapshot>> ListSnapshotsAsync(ClusterConfig cluster, VmRef vm, CancellationToken ct);

    /// <summary>Cria snapshot sem vmstate e espera a task terminar. Lança <see cref="ProxmoxException"/> se o storage não suportar.</summary>
    Task CreateSnapshotAsync(ClusterConfig cluster, VmRef vm, string name, string description, CancellationToken ct);

    Task DeleteSnapshotAsync(ClusterConfig cluster, VmRef vm, string name, CancellationToken ct);

    /// <summary>Faz ping no guest agent até responder ou estourar o timeout.</summary>
    Task<bool> WaitForGuestAgentAsync(ClusterConfig cluster, VmRef vm, TimeSpan timeout, CancellationToken ct);
}

public class ProxmoxException(string message, Exception? inner = null) : Exception(message, inner);

public enum PveLoginStatus { Success, NeedTotp, Failed }

/// <param name="Ticket">PVEAuthCookie (ou o ticket parcial quando NeedTotp).</param>
public sealed record PveLoginResult(PveLoginStatus Status, string? UserId, string? Ticket, string? CsrfToken, string? Error);

/// <summary>Autenticação de usuários da UI contra o PVE (ticket do próprio usuário, não o token de serviço).</summary>
public interface IProxmoxAuth
{
    /// <param name="userId">"usuario@realm", ex.: "root@pam".</param>
    Task<PveLoginResult> LoginAsync(ClusterConfig cluster, string userId, string password, CancellationToken ct);

    /// <summary>Segunda etapa quando o login devolveu NeedTotp.</summary>
    Task<PveLoginResult> CompleteTotpAsync(ClusterConfig cluster, string userId, string partialTicket, string totpCode, CancellationToken ct);

    /// <summary>GET /access/permissions com o ticket do usuário: caminho ACL → privilégios efetivos.</summary>
    Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> GetPermissionsAsync(ClusterConfig cluster, string ticket, CancellationToken ct);
}

/// <summary>Como escolher o IP de SSH de uma VM.</summary>
public enum IpOverrideMode { Auto, Nic, Fixed }

/// <param name="Value">Nic: MAC (preferido) ou nome da interface; Fixed: o IP literal.</param>
public sealed record IpOverride(IpOverrideMode Mode, string? Value);

public interface IIpSelector
{
    /// <summary>
    /// Auto: IPv4 primeiro, ignora loopback/link-local/docker/veth/br-/virbr/cni/flannel/cali/tun,
    /// prefere endereços dentro de <paramref name="preferredNetworks"/>.
    /// Nic: primeiro IPv4 (senão IPv6 global) da NIC indicada. Fixed: o valor.
    /// </summary>
    IPAddress? Select(DiscoveredVm vm, IpOverride? ipOverride, IReadOnlyList<IPNetwork> preferredNetworks);
}

/// <summary>Permissões efetivas do token de serviço (não do usuário logado), para diagnosticar o cluster.</summary>
public interface IProxmoxServicePermissions
{
    /// <summary>GET /access/permissions com o token de serviço: caminho ACL → privilégios efetivos. Vazio = ACL vazia.</summary>
    Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> GetServicePermissionsAsync(ClusterConfig cluster, CancellationToken ct);
}
