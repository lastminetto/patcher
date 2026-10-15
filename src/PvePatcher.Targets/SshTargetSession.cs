using System.Text;
using PvePatcher.Core;
using Renci.SshNet;

namespace PvePatcher.Targets;

public sealed class SshTargetSession(SshClient client, string hostKeySha256) : ITargetSession
{
    public string HostKeySha256 { get; } = hostKeySha256;

    public async Task<CommandResult> RunAgentAsync(string subcommand, IReadOnlyList<string> args, Action<string>? onLine, TimeSpan timeout, CancellationToken ct)
    {
        var user = client.ConnectionInfo.Username;
        var text = ShellQuote.BuildAgentCommand(subcommand, args, user);
        using var cmd = client.CreateCommand(text, Encoding.UTF8);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);

        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        var gate = new object();
        var outTask = PumpAsync(cmd.OutputStream, stdout, onLine, gate);
        var errTask = PumpAsync(cmd.ExtendedOutputStream, stderr, onLine, gate);

        try
        {
            // O SSH.NET só entrega o stdin com o comando já em execução; o script vai por ele e o Dispose envia o EOF.
            var exec = cmd.ExecuteAsync(cts.Token);
            var input = cmd.CreateInputStream();
            try
            {
                var bytes = new UTF8Encoding(false).GetBytes(AgentScript.Text);
                await input.WriteAsync(bytes, cts.Token).ConfigureAwait(false);
                await input.FlushAsync(cts.Token).ConfigureAwait(false);
            }
            finally
            {
                try { input.Dispose(); } catch { /* canal já fechado pelo remoto (ex.: sudo negado) */ }
            }
            await exec.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            await DrainAsync(outTask, errTask).ConfigureAwait(false);
            if (ct.IsCancellationRequested) throw;
            throw new TargetException($"Tempo esgotado ({timeout.TotalSeconds:0}s) em '{subcommand}'");
        }
        await Task.WhenAll(outTask, errTask).ConfigureAwait(false);

        var exit = cmd.ExitStatus ?? -1;
        var so = stdout.ToString();
        var se = stderr.ToString();
        if (SudoError(user, exit, se) is { } msg) throw new TargetException(msg);
        return new CommandResult(exit, so, se);
    }

    /// <summary>Mensagem em pt-BR quando o sudo não deixou rodar sem senha/terminal; null se o erro é outro.</summary>
    public static string? SudoError(string user, int exit, string stderr)
    {
        if (exit == 0) return null;
        var sudo = stderr.Contains("sudo: a password is required", StringComparison.Ordinal)
            || stderr.Contains("sudo: a terminal is required", StringComparison.Ordinal)
            || stderr.Contains("requiretty", StringComparison.OrdinalIgnoreCase)
            || stderr.Contains("is not in the sudoers", StringComparison.Ordinal)
            || stderr.Contains("sudo: command not found", StringComparison.Ordinal)
            || (exit == 127 && stderr.Contains("sudo: not found", StringComparison.Ordinal));
        return sudo
            ? $"A conta '{user}' precisa ser root ou ter sudo NOPASSWD (sem requiretty) na VM."
            : null;
    }

    private static async Task DrainAsync(params Task[] pumps)
    {
        try { await Task.WhenAny(Task.WhenAll(pumps), Task.Delay(TimeSpan.FromSeconds(2))).ConfigureAwait(false); }
        catch { /* leitores terminam com o canal fechado */ }
    }

    private static async Task PumpAsync(Stream stream, StringBuilder sink, Action<string>? onLine, object gate)
    {
        using var reader = new StreamReader(stream, Encoding.UTF8, false, 4096, leaveOpen: true);
        while (await reader.ReadLineAsync().ConfigureAwait(false) is { } line)
        {
            lock (gate) sink.Append(line).Append('\n');
            if (onLine is null) continue;
            try { onLine(line); } catch { /* o log nunca derruba o comando */ }
        }
    }

    public ValueTask DisposeAsync()
    {
        try { if (client.IsConnected) client.Disconnect(); } catch { }
        client.Dispose();
        return ValueTask.CompletedTask;
    }
}
