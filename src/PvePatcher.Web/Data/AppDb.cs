using Microsoft.EntityFrameworkCore;

namespace PvePatcher.Web.Data;

public sealed class AppDb(DbContextOptions<AppDb> options) : DbContext(options)
{
    public DbSet<ClusterEntity> Clusters => Set<ClusterEntity>();
    public DbSet<VmEntity> Vms => Set<VmEntity>();
    public DbSet<SettingEntity> Settings => Set<SettingEntity>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<ClusterEntity>().Ignore(c => c.Endpoints);
        b.Entity<VmEntity>(e =>
        {
            e.HasKey(v => new { v.ClusterId, v.VmId });
            e.Ignore(v => v.Os).Ignore(v => v.Nics).Ignore(v => v.Scan).Ignore(v => v.Findings)
                .Ignore(v => v.IsRunning).Ignore(v => v.Key);
        });
    }
}

/// <summary>Fábrica para <c>dotnet ef migrations</c>.</summary>
public sealed class AppDbDesignFactory : Microsoft.EntityFrameworkCore.Design.IDesignTimeDbContextFactory<AppDb>
{
    public AppDb CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<AppDb>().UseSqlite("Data Source=design.db").Options);
}
