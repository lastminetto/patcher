using PvePatcher.Core;

namespace PvePatcher.Web.Services;

/// <summary>Acompanha o estado do cofre para o banner global e para falhar jobs cedo.</summary>
public sealed class VaultMonitor(ISecretStore vault, AppEvents events, ILogger<VaultMonitor> log) : BackgroundService
{
    public VaultStatus Current { get; private set; } = new(VaultState.Unreachable, "ainda não verificado");

    public bool IsReady => Current.State == VaultState.Ready;

    public string Banner => Current.State switch
    {
        VaultState.Ready => "",
        VaultState.Sealed => VaultMessages.Sealed,
        VaultState.AuthFailed => "Cofre: falha de autenticação do serviço (AppRole) — verifique init-openbao",
        _ => "Cofre inacessível — verifique o serviço openbao no LXC",
    };

    public async Task<VaultStatus> RefreshAsync(CancellationToken ct = default)
    {
        VaultStatus status;
        try { status = await vault.GetStatusAsync(ct); }
        catch (VaultUnavailableException ex) { status = ex.Status; }
        catch (Exception ex) when (ex is not OperationCanceledException) { status = new(VaultState.Unreachable, ex.Message); }

        if (status.State != Current.State)
        {
            log.LogInformation("Cofre: {Old} -> {New} {Detail}", Current.State, status.State, status.Detail);
            Current = status;
            events.RaiseData();
        }
        else Current = status;
        return status;
    }

    /// <summary>Verificação fresca antes de um job que precisa de segredos.</summary>
    public async Task EnsureReadyAsync(CancellationToken ct)
    {
        var s = await RefreshAsync(ct);
        if (s.State != VaultState.Ready) throw new VaultUnavailableException(s);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await RefreshAsync(stoppingToken);
            try { await Task.Delay(Current.State == VaultState.Ready ? TimeSpan.FromSeconds(60) : TimeSpan.FromSeconds(15), stoppingToken); }
            catch (OperationCanceledException) { }
        }
    }
}
