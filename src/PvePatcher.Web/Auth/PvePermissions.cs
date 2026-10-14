using System.Security.Claims;

namespace PvePatcher.Web.Auth;

/// <summary>
/// Permissões efetivas do usuário no cluster em que ele fez login (GET /access/permissions).
/// O PVE devolve os privilégios já propagados por caminho; a herança aqui é só a consulta
/// <c>/vms/{id}</c> -> <c>/vms</c> -> <c>/</c>.
/// </summary>
public sealed class PvePermissions(IReadOnlyDictionary<string, IReadOnlySet<string>> map)
{
    public const string ViewPrivilege = "Sys.Audit";
    public const string ModifyPrivilege = "Sys.Modify";
    public const string VmPrivilege = "VM.PowerMgmt";
    public const string ClaimType = "pve_perm";

    public static readonly PvePermissions None = new(new Dictionary<string, IReadOnlySet<string>>());

    public bool Has(string path, string privilege) =>
        map.TryGetValue(path, out var set) && set.Contains(privilege);

    /// <summary>Ver a UI: Sys.Audit em /.</summary>
    public bool CanView => Has("/", ViewPrivilege);

    /// <summary>Clusters, segredos e configurações: Sys.Modify em /.</summary>
    public bool CanAdmin => Has("/", ModifyPrivilege);

    /// <summary>Escanear/atualizar/alterar IP: VM.PowerMgmt em /vms/{id}, /vms ou /.</summary>
    public bool CanOperateVm(int vmId) =>
        Has($"/vms/{vmId}", VmPrivilege) || Has("/vms", VmPrivilege) || Has("/", VmPrivilege);

    // Um claim por caminho: "caminho\tPriv1,Priv2".
    public IEnumerable<Claim> ToClaims() =>
        map.Select(kv => new Claim(ClaimType, kv.Key + "\t" + string.Join(',', kv.Value)));

    public static PvePermissions FromClaims(IEnumerable<Claim> claims)
    {
        var dict = new Dictionary<string, IReadOnlySet<string>>();
        foreach (var c in claims.Where(c => c.Type == ClaimType))
        {
            var i = c.Value.IndexOf('\t');
            if (i < 0) continue;
            dict[c.Value[..i]] = c.Value[(i + 1)..].Split(',', StringSplitOptions.RemoveEmptyEntries).ToHashSet();
        }
        return new PvePermissions(dict);
    }
}

/// <summary>Usuário logado: o cluster de origem, o id (user@realm) e as permissões.</summary>
public sealed record UserInfo(string ClusterId, string UserId, PvePermissions Permissions)
{
    public const string ClusterClaim = "pve_cluster";

    /// <summary>Só vale para VMs do cluster em que o usuário logou.</summary>
    public bool CanOperate(string clusterId, int vmId) =>
        string.Equals(clusterId, ClusterId, StringComparison.Ordinal) && Permissions.CanOperateVm(vmId);

    public bool CanAdmin => Permissions.CanAdmin;

    public static UserInfo? FromPrincipal(ClaimsPrincipal? p)
    {
        if (p?.Identity?.IsAuthenticated != true) return null;
        var cluster = p.FindFirst(ClusterClaim)?.Value;
        var user = p.Identity.Name;
        return cluster is null || user is null ? null : new UserInfo(cluster, user, PvePermissions.FromClaims(p.Claims));
    }

    public ClaimsPrincipal ToPrincipal()
    {
        var claims = new List<Claim> { new(ClaimTypes.Name, UserId), new(ClusterClaim, ClusterId) };
        claims.AddRange(Permissions.ToClaims());
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "pve", ClaimTypes.Name, ClaimTypes.Role));
    }
}
