using Cronos;

namespace PvePatcher.Web.Services;

public static class CronHelper
{
    public static bool TryParse(string? expr, out CronExpression? cron)
    {
        cron = null;
        return !string.IsNullOrWhiteSpace(expr) && CronExpression.TryParse(expr.Trim(), CronFormat.Standard, out cron);
    }

    public static TimeZoneInfo Zone(string id)
    {
        foreach (var candidate in new[] { id, "E. South America Standard Time" })
        {
            try { return TimeZoneInfo.FindSystemTimeZoneById(candidate); } catch { }
        }
        return TimeZoneInfo.Utc;
    }

    public static DateTimeOffset? Next(string expr, string zoneId, DateTimeOffset from)
    {
        if (!TryParse(expr, out var cron)) return null;
        var n = cron!.GetNextOccurrence(from.UtcDateTime, Zone(zoneId));
        return n is null ? null : new DateTimeOffset(DateTime.SpecifyKind(n.Value, DateTimeKind.Utc));
    }
}

/// <summary>
/// Ciclo agendado: atualiza os feeds e varre todas as VMs ligadas, uma por vez (tudo pela fila).
/// A fila serial garante a ordem: feeds primeiro, depois os scans.
/// </summary>
public sealed class SchedulerService(
    SettingsService settings, StateStore store, OperationsService ops, TimeProvider time, ILogger<SchedulerService> log) : BackgroundService
{
    public const string LastCycleKey = "lastCycle";

    public DateTimeOffset? NextRun()
    {
        var s = settings.Current;
        return s.ScanEnabled ? CronHelper.Next(s.ScanCron, s.TimeZone, time.GetUtcNow()) : null;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var system = new UserInfo("", "agendador", PvePermissions.None);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var next = NextRun();
                if (next is null) { await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken); continue; }
                var wait = next.Value - time.GetUtcNow();
                if (wait > TimeSpan.FromMinutes(1)) { await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken); continue; }
                if (wait > TimeSpan.Zero) await Task.Delay(wait, stoppingToken);
                await RunCycleAsync(system);
                await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                log.LogError(ex, "Falha no agendador");
                try { await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken); } catch (OperationCanceledException) { break; }
            }
        }
    }

    public async Task RunCycleAsync(UserInfo system)
    {
        log.LogInformation("Iniciando ciclo agendado");
        ops.EnqueueFeedUpdate(system, scheduled: true);
        var n = 0;
        foreach (var vm in (await store.GetVmsAsync()).Where(v => v.IsRunning).OrderBy(v => v.Name))
            if (ops.EnqueueScan(system, vm.Key, vm.Name, scheduled: true) is not null) n++;
        await settings.SetRawAsync(LastCycleKey, time.GetUtcNow().ToString("O"));
        log.LogInformation("Ciclo agendado: {N} scans enfileirados", n);
    }

    public async Task<DateTimeOffset?> GetLastCycleAsync() =>
        DateTimeOffset.TryParse(await settings.GetRawAsync(LastCycleKey), out var d) ? d : null;
}
