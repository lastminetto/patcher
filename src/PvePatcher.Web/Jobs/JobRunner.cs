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
        catch (VaultUnavailableException)
        {
            status = JobStatus.Failed;
            message = VaultMessages.Sealed;
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
