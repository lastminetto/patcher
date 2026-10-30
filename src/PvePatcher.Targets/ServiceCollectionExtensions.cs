using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PvePatcher.Core;

namespace PvePatcher.Targets;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddPvePatcherTargets(this IServiceCollection services, IConfiguration config)
    {
        services.AddOptions<SshOptions>().Bind(config.GetSection("Ssh"));
        services.AddSingleton<ITargetConnector, SshTargetConnector>();
        services.AddSingleton<IConsoleConnector, SshConsoleConnector>();
        services.AddSingleton<IHostScanner, HostScanner>();
        services.AddSingleton<IHostUpdater, HostUpdater>();
        return services;
    }
}
