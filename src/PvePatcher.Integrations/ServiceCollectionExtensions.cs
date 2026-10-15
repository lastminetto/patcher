using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PvePatcher.Core;
using PvePatcher.Integrations.OpenBao;
using PvePatcher.Integrations.Proxmox;

namespace PvePatcher.Integrations;

public static class ServiceCollectionExtensions
{
    /// <summary>Registra cofre (OpenBao), cliente/autenticação do Proxmox e seletor de IP.</summary>
    public static IServiceCollection AddPvePatcherIntegrations(this IServiceCollection services, IConfiguration config)
    {
        var options = config.GetSection(OpenBaoOptions.Section).Get<OpenBaoOptions>() ?? new OpenBaoOptions();
        services.AddSingleton(options);
        services.AddSingleton<ISecretStore>(sp => new OpenBaoSecretStore(
            new HttpClient(new SocketsHttpHandler { ConnectTimeout = TimeSpan.FromSeconds(5) }) { Timeout = TimeSpan.FromSeconds(15) },
            sp.GetRequiredService<OpenBaoOptions>()));

        services.AddSingleton<PveHttp>(_ => new PveHttp());
        services.AddSingleton(new ProxmoxClientOptions());
        services.AddSingleton<ProxmoxClient>();
        services.AddSingleton<IProxmoxClient>(sp => sp.GetRequiredService<ProxmoxClient>());
        services.AddSingleton<IProxmoxServicePermissions>(sp => sp.GetRequiredService<ProxmoxClient>());
        services.AddSingleton<IProxmoxAuth, ProxmoxAuth>();
        services.AddSingleton<IIpSelector, IpSelector>();
        return services;
    }
}
