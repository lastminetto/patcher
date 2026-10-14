using Microsoft.Extensions.Logging.Abstractions;
using PvePatcher.Web.Data;
using PvePatcher.Web.Jobs;
using PvePatcher.Web.Services;

namespace PvePatcher.Web.Tests;

public class JobRunnerTests
{
    private sealed class Probe : IJobExecutor
    {
        private int _running;
        public int MaxConcurrent;
        public readonly List<string> Order = [];

        public async Task<string?> ExecuteAsync(Job job, CancellationToken ct)
        {
            var now = Interlocked.Increment(ref _running);
            lock (Order) { MaxConcurrent = Math.Max(MaxConcurrent, now); Order.Add(job.Title); }
            await Task.Delay(30, ct);
            Interlocked.Decrement(ref _running);
            if (job.Title == "boom") throw new JobFailedException("falhou");
            return "ok";
        }

        public Task OnFinishedAsync(Job job) => Task.CompletedTask;
    }

    private static Job J(string title, VmKey? vm = null) => new() { Kind = JobKind.Scan, Title = title, Vm = vm };

    [Fact]
    public async Task NeverRunsTwoJobsAtOnce_AndKeepsOrder()
    {
        var queue = new JobQueue(new AppEvents());
        var probe = new Probe();
        var runner = new JobRunner(queue, probe, NullLogger<JobRunner>.Instance);

        var jobs = Enumerable.Range(0, 8).Select(i => queue.Enqueue(J("j" + i))).ToList();
        jobs.Add(queue.Enqueue(J("boom")));
        await runner.StartAsync(default);
        await WaitAsync(() => jobs.All(j => j.Status is JobStatus.Succeeded or JobStatus.Failed));
        await runner.StopAsync(default);

        Assert.Equal(1, probe.MaxConcurrent);
        Assert.Equal(jobs.Select(j => j.Title), probe.Order);
        Assert.Equal(JobStatus.Failed, jobs[^1].Status);
        Assert.Equal("falhou", jobs[^1].Message);
    }

    [Fact]
    public async Task CancelledPendingJob_IsSkipped()
    {
        var queue = new JobQueue(new AppEvents());
        var probe = new Probe();
        var a = queue.Enqueue(J("a"));
        var b = queue.Enqueue(J("b"));
        Assert.True(queue.Cancel(b.Id));
        var runner = new JobRunner(queue, probe, NullLogger<JobRunner>.Instance);

        await runner.StartAsync(default);
        await WaitAsync(() => a.Status == JobStatus.Succeeded);
        await runner.StopAsync(default);

        Assert.Equal(["a"], probe.Order);
        Assert.Equal(JobStatus.Cancelled, b.Status);
    }

    [Fact]
    public void RunningUpgrade_CannotBeCancelled_ButScanCan()
    {
        var queue = new JobQueue(new AppEvents());
        var up = queue.Enqueue(new Job { Kind = JobKind.Upgrade, Title = "u" });
        var sc = queue.Enqueue(J("s"));
        queue.MarkStarted(up);
        Assert.False(queue.Cancel(up.Id));
        queue.MarkFinished(up, JobStatus.Succeeded, null);
        queue.MarkStarted(sc);
        Assert.True(queue.Cancel(sc.Id));
        Assert.True(sc.Cts.IsCancellationRequested);
    }

    private static async Task WaitAsync(Func<bool> cond)
    {
        for (var i = 0; i < 200 && !cond(); i++) await Task.Delay(25);
        Assert.True(cond(), "timeout");
    }
}
