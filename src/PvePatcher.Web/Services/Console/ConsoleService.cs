using PvePatcher.Core;

namespace PvePatcher.Web.Services;

/// <summary>Abre shells e sessões SFTP do terminal para uma VM (chave ssh/console, usuário fixo), com log de auditoria.</summary>
public sealed class ConsoleService(VmConnectionResolver resolver, IConsoleConnector connector, ILogger<ConsoleService> log)
{
    /// <summary>Abre o shell. Erros esperados viram <see cref="JobFailedException"/> com mensagem para o usuário.</summary>
    public async Task<(IShellSession Shell, SshTarget Target)> OpenShellAsync(string appUser, VmKey key, int cols, int rows, CancellationToken ct)
    {
        var target = await ResolveAsync(key, ct);
        var shell = await Guard(() => resolver.ConnectAsync(key, target, t => connector.OpenShellAsync(t, cols, rows, ct), s => s.HostKeySha256, null));
        log.LogInformation("Terminal aberto: {AppUser} em {Vm} como {User}@{Host}:{Port}", appUser, key, target.User, target.Host, target.Port);
        return (shell, target);
    }

    public void LogClosed(string appUser, VmKey key, TimeSpan duration, long bytesIn, long bytesOut, string? reason) =>
        log.LogInformation("Terminal fechado: {AppUser} em {Vm} após {Duration:hh\\:mm\\:ss} ({In} bytes enviados, {Out} recebidos){Reason}",
            appUser, key, duration, bytesIn, bytesOut, reason is null ? "" : $": {reason}");

    /// <summary>Roda uma operação numa sessão SFTP nova (uma conexão por operação).</summary>
    public async Task<T> WithSftpAsync<T>(string appUser, VmKey key, string what, Func<ISftpSession, Task<T>> action, CancellationToken ct)
    {
        var target = await ResolveAsync(key, ct);
        await using var sftp = await Guard(() => resolver.ConnectAsync(key, target, t => connector.OpenSftpAsync(t, ct), s => s.HostKeySha256, null));
        try
        {
            var r = await action(sftp);
            if (what.Length > 0) log.LogInformation("SFTP: {AppUser} em {Vm}: {What}", appUser, key, what);
            return r;
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not JobFailedException)
        {
            throw new JobFailedException(Friendly(ex), ex);
        }
    }

    public Task WithSftpAsync(string appUser, VmKey key, string what, Func<ISftpSession, Task> action, CancellationToken ct) =>
        WithSftpAsync(appUser, key, what, async s => { await action(s); return true; }, ct);

    private async Task<SshTarget> ResolveAsync(VmKey key, CancellationToken ct)
    {
        try { return await resolver.ForConsoleAsync(key, ct); }
        catch (VaultUnavailableException ex) { throw new JobFailedException(VaultMessages.For(ex), ex); }
    }

    private static async Task<T> Guard<T>(Func<Task<T>> connect)
    {
        try { return await connect(); }
        catch (TargetException ex) { throw new JobFailedException(ex.Message, ex); }
    }

    private static string Friendly(Exception ex) => ex switch
    {
        Renci.SshNet.Common.SftpPermissionDeniedException => "Permissão negada no servidor.",
        Renci.SshNet.Common.SftpPathNotFoundException => "Caminho não encontrado.",
        _ => ex.Message,
    };
}
