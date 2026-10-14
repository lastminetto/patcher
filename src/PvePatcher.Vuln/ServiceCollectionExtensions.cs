using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PvePatcher.Core;

namespace PvePatcher.Vuln;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registra o matcher e o atualizador de feeds. Opções na seção "Vuln"
    /// (DatabasePath, CacheDir). Requer ISecretStore (opcional) registrado por outro módulo.
    /// </summary>
    public static IServiceCollection AddPvePatcherVuln(this IServiceCollection services, IConfiguration config)
    {
        services.Configure<VulnOptions>(config.GetSection("Vuln"));
        services.AddHttpClient(VulnFeedUpdater.HttpClientName, c =>
        {
            c.Timeout = TimeSpan.FromMinutes(30); // all.zip do Ubuntu passa de 700 MB
            c.DefaultRequestHeaders.UserAgent.ParseAdd("pve-patcher/1.0");
        });
        services.AddSingleton<VulnDatabase>();
        services.AddSingleton<IVulnerabilityMatcher, VulnerabilityMatcher>();
        services.AddSingleton<IVulnFeedUpdater, VulnFeedUpdater>();
        return services;
    }
}
