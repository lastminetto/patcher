using Microsoft.EntityFrameworkCore;

namespace PvePatcher.Web.Data;

/// <summary>Cluster semeado a partir da configuração (Bootstrap:Clusters).</summary>
public sealed class BootstrapCluster
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public List<string> Endpoints { get; set; } = [];
    public string? CertFingerprintSha256 { get; set; }
}

public static class DbInitializer
{
    /// <summary>Cria/migra o banco, ativa WAL e semeia os clusters de Bootstrap:Clusters que ainda não existem.</summary>
    public static async Task InitializeAsync(IServiceProvider services, IConfiguration config)
    {
        var factory = services.GetRequiredService<IDbContextFactory<AppDb>>();
        await using var db = await factory.CreateDbContextAsync();
        await db.Database.MigrateAsync();
        await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;");

        var seeds = config.GetSection("Bootstrap:Clusters").Get<List<BootstrapCluster>>() ?? [];
        foreach (var s in seeds.Where(s => !string.IsNullOrWhiteSpace(s.Id) && s.Endpoints.Count > 0))
        {
            var id = s.Id.Trim().ToLowerInvariant();
            if (await db.Clusters.AnyAsync(c => c.Id == id)) continue;
            db.Clusters.Add(new ClusterEntity
            {
                Id = id,
                Name = string.IsNullOrWhiteSpace(s.Name) ? s.Id : s.Name,
                Endpoints = s.Endpoints,
                Fingerprint = s.CertFingerprintSha256,
            });
        }
        await db.SaveChangesAsync();
    }
}
