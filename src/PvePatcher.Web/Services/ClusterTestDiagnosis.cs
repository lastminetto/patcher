using PvePatcher.Core;

namespace PvePatcher.Web.Services;

/// <param name="Message">Texto para a UI.</param>
/// <param name="Warning">true quando a conexão funciona mas o resultado indica problema de permissão/agent.</param>
public sealed record ClusterTestResult(string Message, bool Warning);

/// <summary>Interpreta o resultado do dry-run do discovery junto com as permissões do token de serviço.</summary>
public static class ClusterTestDiagnosis
{
    public const string Audit = "VM.Audit";
    public const string GuestAgentAudit = "VM.GuestAgent.Audit"; // PVE 9
    public const string Monitor = "VM.Monitor";                  // PVE 8

    /// <param name="perms">Permissões do token de serviço; null se não foram consultadas (ou a consulta falhou).</param>
    public static ClusterTestResult Evaluate(IReadOnlyList<DiscoveredVm> vms, IReadOnlyDictionary<string, IReadOnlySet<string>>? perms)
    {
        if (vms.Count == 0)
        {
            if (perms is not null && perms.Count == 0)
                return new("Conexão OK, mas 0 VMs. Token sem permissões (ACL vazia). Com Privilege Separation, dê a role ao usuário E ao token em Datacenter → Permissions, path /.", true);
            if (perms is not null && !Has(perms, Audit))
                return new($"Conexão OK, mas 0 VMs: o token não tem {Audit}. Atribua uma role com {Audit} ao usuário E ao token em Datacenter → Permissions, path /.", true);
            return new("Conexão OK, mas 0 VMs QEMU encontradas (dry-run, nada foi gravado). Se o cluster tem VMs, revise as permissões do token.", true);
        }

        var nodes = vms.Select(v => v.Node).Distinct().Count();
        var ok = $"Conexão OK: {vms.Count} VM(s) QEMU em {nodes} nó(s) (dry-run, nada foi gravado).";
        if (vms.Any(v => v.Status == "running") && !vms.Any(v => v.AgentResponding))
        {
            var hint = perms is not null && !Has(perms, GuestAgentAudit) && !Has(perms, Monitor)
                ? $"o token não tem {GuestAgentAudit} (PVE 9) nem {Monitor} (PVE 8)"
                : "falta a permissão " + GuestAgentAudit + " (PVE 9) / " + Monitor + " (PVE 8) no token, ou o qemu-guest-agent não está rodando nas VMs";
            return new($"{ok} Nenhuma VM respondeu ao guest agent: {hint}. Sem isso não há IP nem SO automáticos (use IP manual).", true);
        }
        return new(ok, false);
    }

    private static bool Has(IReadOnlyDictionary<string, IReadOnlySet<string>> perms, string priv) =>
        perms.Values.Any(p => p.Contains(priv));
}
