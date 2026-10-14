using System.Net;
using Microsoft.EntityFrameworkCore;
using PvePatcher.Core;

namespace PvePatcher.Web.Data;

/// <summary>Configurações editáveis na UI (uma linha JSON). Segredos nunca entram aqui.</summary>
public sealed class AppSettings
{
    public string SshUser { get; set; } = "patcher";
    public List<string> PreferredNetworks { get; set; } = [];
    public string ScanCron { get; set; } = "0 3 * * *";
    public string TimeZone { get; set; } = "America/Sao_Paulo";
    public bool ScanEnabled { get; set; } = true;
    public int DiscoveryMinutes { get; set; } = 15;
    public double CriticalCvss { get; set; } = 9.0;
    public double HighCvss { get; set; } = 7.0;
    public double HighEpss { get; set; } = 0.5;
    public double MediumCvss { get; set; } = 4.0;
    /// <summary>Quando cada segredo foi gravado (só a data; o valor fica no cofre).</summary>
    public Dictionary<string, DateTimeOffset> SecretsSetAt { get; set; } = new();

    public SeverityThresholds Thresholds => new(CriticalCvss, HighCvss, HighEpss, MediumCvss);

    public IReadOnlyList<IPNetwork> ParsePreferredNetworks() =>
        PreferredNetworks.Select(s => IPNetwork.TryParse(s.Trim(), out var n) ? n : (IPNetwork?)null)
            .Where(n => n.HasValue).Select(n => n!.Value).ToList();
}

public sealed class SettingsService(IDbContextFactory<AppDb> factory, AppEvents events)
{
    private const string Key = "app";
    private AppSettings? _cache;

    public AppSettings Current => _cache ??= Load();

    private AppSettings Load()
    {
        using var db = factory.CreateDbContext();
        return Json.Deserialize<AppSettings>(db.Settings.Find(Key)?.Value) ?? new AppSettings();
    }

    public async Task SaveAsync(AppSettings s)
    {
        await using var db = await factory.CreateDbContextAsync();
        var row = await db.Settings.FindAsync(Key);
        if (row is null) db.Settings.Add(new SettingEntity { Key = Key, Value = Json.Serialize(s) });
        else row.Value = Json.Serialize(s);
        await db.SaveChangesAsync();
        _cache = s;
        events.RaiseData();
    }

    public async Task MarkSecretAsync(string name, DateTimeOffset at)
    {
        var s = Current;
        s.SecretsSetAt[name] = at;
        await SaveAsync(s);
    }

    public async Task<string?> GetRawAsync(string key)
    {
        await using var db = await factory.CreateDbContextAsync();
        return (await db.Settings.FindAsync(key))?.Value;
    }

    public async Task SetRawAsync(string key, string value)
    {
        await using var db = await factory.CreateDbContextAsync();
        var row = await db.Settings.FindAsync(key);
        if (row is null) db.Settings.Add(new SettingEntity { Key = key, Value = value });
        else row.Value = value;
        await db.SaveChangesAsync();
        events.RaiseData();
    }
}

/// <summary>Acesso ao SQLite. Cada chamada usa um contexto curto.</summary>
public sealed class StateStore(IDbContextFactory<AppDb> factory, AppEvents events)
{
    public async Task<List<ClusterEntity>> GetClustersAsync()
    {
        await using var db = await factory.CreateDbContextAsync();
        return (await db.Clusters.AsNoTracking().ToListAsync()).OrderBy(c => c.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public async Task<ClusterEntity?> GetClusterAsync(string id)
    {
        await using var db = await factory.CreateDbContextAsync();
        return await db.Clusters.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id);
    }

    public async Task UpsertClusterAsync(ClusterEntity c)
    {
        await using var db = await factory.CreateDbContextAsync();
        var row = await db.Clusters.FindAsync(c.Id);
        if (row is null) db.Clusters.Add(c);
        else { row.Name = c.Name; row.EndpointsJson = c.EndpointsJson; row.Fingerprint = c.Fingerprint; }
        await db.SaveChangesAsync();
        events.RaiseData();
    }

    public async Task DeleteClusterAsync(string id)
    {
        await using var db = await factory.CreateDbContextAsync();
        db.Vms.RemoveRange(db.Vms.Where(v => v.ClusterId == id));
        db.Clusters.RemoveRange(db.Clusters.Where(c => c.Id == id));
        await db.SaveChangesAsync();
        events.RaiseData();
    }

    public async Task<List<VmEntity>> GetVmsAsync()
    {
        await using var db = await factory.CreateDbContextAsync();
        return await db.Vms.AsNoTracking().ToListAsync();
    }

    public async Task<VmEntity?> GetVmAsync(VmKey key)
    {
        await using var db = await factory.CreateDbContextAsync();
        return await db.Vms.AsNoTracking().FirstOrDefaultAsync(v => v.ClusterId == key.ClusterId && v.VmId == key.VmId);
    }

    /// <summary>Carrega, aplica a mudança e grava. Devolve null se a VM não existe mais.</summary>
    public async Task<VmEntity?> UpdateVmAsync(VmKey key, Action<VmEntity> change)
    {
        await using var db = await factory.CreateDbContextAsync();
        var vm = await db.Vms.FirstOrDefaultAsync(v => v.ClusterId == key.ClusterId && v.VmId == key.VmId);
        if (vm is null) return null;
        change(vm);
        await db.SaveChangesAsync();
        events.RaiseData();
        return vm;
    }
}
