using System.Threading.Channels;

namespace PvePatcher.Web.Jobs;

public enum JobKind { Scan, Upgrade, FeedUpdate }

public enum JobStatus { Pending, Running, Succeeded, Failed, Cancelled }

/// <param name="Snapshot">Snapshot do PVE antes do upgrade.</param>
/// <param name="Reboot">Reiniciar se o upgrade exigir.</param>
/// <param name="SecurityOnly">Só os pacotes que corrigem CVE (UpgradeMode.Packages).</param>
public sealed record UpgradeOptions(bool Snapshot, bool Reboot, bool SecurityOnly);

/// <summary>Falha esperada de um job; a mensagem vai direto para o usuário.</summary>
public class JobFailedException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>Conexão bloqueada por host key divergente (não adianta repetir).</summary>
public sealed class HostKeyBlockedException(string message) : JobFailedException(message);

public sealed class Job
{
    private const int MaxLines = 5000;
    private readonly object _lock = new();
    private readonly List<string> _lines = [];

    public Guid Id { get; } = Guid.NewGuid();
    public JobKind Kind { get; init; }
    public VmKey? Vm { get; init; }
    public string Title { get; init; } = "";
    public UpgradeOptions? Upgrade { get; init; }
    public string RequestedBy { get; init; } = "";
    public bool Scheduled { get; init; }
    public DateTimeOffset EnqueuedAt { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? FinishedAt { get; set; }
    public JobStatus Status { get; set; } = JobStatus.Pending;
    public string? Message { get; set; }
    public CancellationTokenSource Cts { get; } = new();

    /// <summary>Só scans e atualização de feeds podem ser interrompidos; upgrade em andamento não.</summary>
    public bool CancelableWhileRunning => Kind != JobKind.Upgrade;

    public int LineCount { get { lock (_lock) return _lines.Count; } }

    public void Log(string line)
    {
        lock (_lock)
        {
            if (_lines.Count >= MaxLines) _lines.RemoveRange(0, MaxLines / 10);
            _lines.Add(line);
        }
        OnLog?.Invoke();
    }

    public string[] Lines() { lock (_lock) return [.. _lines]; }

    public string Text() { lock (_lock) return string.Join('\n', _lines); }

    internal Action? OnLog { get; set; }
}

/// <summary>Fila em memória (um único consumidor). Jobs cancelados enquanto pendentes são ignorados pelo worker.</summary>
public sealed class JobQueue(AppEvents events)
{
    private const int KeepFinished = 25;
    private readonly Channel<Job> _channel = Channel.CreateUnbounded<Job>(new UnboundedChannelOptions { SingleReader = true });
    private readonly List<Job> _jobs = [];
    private readonly object _lock = new();

    public ChannelReader<Job> Reader => _channel.Reader;

    public Job Enqueue(Job job)
    {
        job.OnLog = events.RaiseLog;
        lock (_lock) _jobs.Add(job);
        _channel.Writer.TryWrite(job);
        events.RaiseData();
        return job;
    }

    /// <summary>Evita enfileirar de novo uma VM que já tem job do mesmo tipo pendente/rodando.</summary>
    public Job? FindActive(JobKind kind, VmKey vm)
    {
        lock (_lock)
            return _jobs.FirstOrDefault(j => j.Kind == kind && j.Vm == vm && j.Status is JobStatus.Pending or JobStatus.Running);
    }

    public bool HasActiveFeedUpdate()
    {
        lock (_lock) return _jobs.Any(j => j.Kind == JobKind.FeedUpdate && j.Status is JobStatus.Pending or JobStatus.Running);
    }

    public IReadOnlyList<Job> Snapshot()
    {
        lock (_lock) return [.. _jobs];
    }

    public Job? Get(Guid id)
    {
        lock (_lock) return _jobs.FirstOrDefault(j => j.Id == id);
    }

    public Job? Current
    {
        get { lock (_lock) return _jobs.FirstOrDefault(j => j.Status == JobStatus.Running); }
    }

    public bool IsVmBusy(VmKey vm)
    {
        lock (_lock) return _jobs.Any(j => j.Vm == vm && j.Status is JobStatus.Pending or JobStatus.Running);
    }

    /// <summary>Pendente: cancela sempre. Rodando: só scan/feed.</summary>
    public bool Cancel(Guid id)
    {
        Job? job;
        lock (_lock) job = _jobs.FirstOrDefault(j => j.Id == id);
        if (job is null) return false;
        lock (_lock)
        {
            if (job.Status == JobStatus.Pending)
            {
                job.Status = JobStatus.Cancelled;
                job.FinishedAt = DateTimeOffset.UtcNow;
                job.Message = "Cancelado antes de iniciar.";
                Trim();
                events.RaiseData();
                return true;
            }
        }
        if (job.Status == JobStatus.Running && job.CancelableWhileRunning)
        {
            job.Cts.Cancel();
            return true;
        }
        return false;
    }

    public void MarkStarted(Job job)
    {
        job.Status = JobStatus.Running;
        job.StartedAt = DateTimeOffset.UtcNow;
        events.RaiseData();
    }

    public void MarkFinished(Job job, JobStatus status, string? message)
    {
        job.Status = status;
        job.Message = message;
        job.FinishedAt = DateTimeOffset.UtcNow;
        lock (_lock) Trim();
        events.RaiseData();
    }

    private void Trim()
    {
        var finished = _jobs.Where(j => j.Status is JobStatus.Succeeded or JobStatus.Failed or JobStatus.Cancelled)
            .OrderBy(j => j.FinishedAt).ToList();
        foreach (var j in finished.Take(Math.Max(0, finished.Count - KeepFinished))) _jobs.Remove(j);
    }
}
