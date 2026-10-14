using PvePatcher.Core;

namespace PvePatcher.Web.Data;

public sealed record ReconcileResult(List<VmEntity> Added, List<VmEntity> Updated, List<VmEntity> Removed);

/// <summary>Reconciliação do resultado do discovery com as VMs já conhecidas de UM cluster.</summary>
public static class VmReconciler
{
    /// <summary>
    /// Novas viram entidades (Added), as existentes são atualizadas in-place (Updated) e as que sumiram
    /// do cluster vão em Removed (o chamador apaga). Sem resposta do agent, NICs e OS anteriores são mantidos.
    /// </summary>
    public static ReconcileResult Reconcile(string clusterId, IReadOnlyCollection<VmEntity> existing, IReadOnlyList<DiscoveredVm> discovered)
    {
        var added = new List<VmEntity>();
        var updated = new List<VmEntity>();
        var byId = existing.ToDictionary(v => v.VmId);
        var seen = new HashSet<int>();

        foreach (var d in discovered)
        {
            if (!seen.Add(d.VmId)) continue;
            if (!byId.TryGetValue(d.VmId, out var vm))
            {
                vm = new VmEntity { ClusterId = clusterId, VmId = d.VmId };
                Apply(vm, d);
                added.Add(vm);
            }
            else
            {
                Apply(vm, d);
                updated.Add(vm);
            }
        }

        var removed = existing.Where(v => !seen.Contains(v.VmId)).ToList();
        return new ReconcileResult(added, updated, removed);
    }

    private static void Apply(VmEntity vm, DiscoveredVm d)
    {
        vm.Node = d.Node;
        vm.Name = d.Name;
        vm.Status = d.Status;
        vm.AgentResponding = d.AgentResponding;
        if (d.AgentResponding)
        {
            vm.Nics = d.Nics.ToList();
            if (d.Os is not null) vm.Os = d.Os;
        }
        else if (d.Nics.Count > 0)
        {
            vm.Nics = d.Nics.ToList();
        }
    }
}
