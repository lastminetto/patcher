using PvePatcher.Core;

namespace PvePatcher.Web.Jobs;

public interface IJobExecutor
{
    /// <summary>Executa o job; lança <see cref="JobFailedException"/> em falhas esperadas. O retorno vira a mensagem de sucesso.</summary>
    Task<string?> ExecuteAsync(Job job, CancellationToken ct);

    /// <summary>Chamado ao fim (qualquer resultado) para gravar o log/resultado na VM.</summary>
    Task OnFinishedAsync(Job job);
}

public static class VaultMessages
{
    public const string Sealed = "Cofre selado — rode unseal no LXC";
    public const string AuthFailed = "Cofre: falha de autenticação do serviço (AppRole) — verifique /etc/pve-patcher/approle e o init-openbao";
    public const string Unreachable = "Cofre inacessível — verifique o serviço openbao no LXC";

    /// <summary>Mensagem do estado real (selado, inacessível ou AppRole recusado), com o detalhe quando houver.</summary>
    public static string For(VaultStatus s)
    {
        var baseMsg = s.State switch
        {
            VaultState.Sealed => Sealed,
            VaultState.AuthFailed => AuthFailed,
            VaultState.Ready => "Cofre disponível",
            _ => Unreachable,
        };
        return string.IsNullOrWhiteSpace(s.Detail) || s.State == VaultState.Sealed ? baseMsg : $"{baseMsg} ({s.Detail})";
    }

    public static string For(VaultUnavailableException ex) => For(ex.Status);
}

/// <summary>Worker único: consome a fila e nunca executa dois jobs ao mesmo tempo.</summary>
public sealed class JobRunner(JobQueue queue, IJobExecutor executor, ILogger<JobRunner> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var job in queue.Reader.ReadAllAsync(stoppingToken))
        {
            if (job.Status != JobStatus.Pending) continue;
            await RunOneAsync(job, stoppingToken);
        }
    }

    public async Task RunOneAsync(Job job, CancellationToken stoppingToken)
    {
        queue.MarkStarted(job);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken, job.Cts.Token);
        JobStatus status;
        string? message;
        try
        {
            message = await executor.ExecuteAsync(job, cts.Token);
            status = JobStatus.Succeeded;
        }
        catch (OperationCanceledException)
        {
            status = JobStatus.Cancelled;
            message = "Cancelado.";
        }
        catch (VaultUnavailableException ex)
        {
            status = JobStatus.Failed;
            message = VaultMessages.For(ex);
        }
        catch (JobFailedException ex)
        {
            status = JobStatus.Failed;
            message = ex.Message;
        }
        catch (Exception ex)
        {
            log.LogError(ex, "Job {Job} falhou", job.Title);
            status = JobStatus.Failed;
            message = ex.Message;
        }

        if (status != JobStatus.Succeeded) job.Log($"!! {message}");
        queue.MarkFinished(job, status, message);
        try { await executor.OnFinishedAsync(job); }
        catch (Exception ex) { log.LogError(ex, "Falha ao gravar o resultado do job {Job}", job.Title); }
    }
}
