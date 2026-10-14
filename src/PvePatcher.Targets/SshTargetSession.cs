using System.Text;
using PvePatcher.Core;
using Renci.SshNet;

namespace PvePatcher.Targets;

public sealed class SshTargetSession(SshClient client, string hostKeySha256) : ITargetSession
{
    private const string NotInstalledMessage = "patcher-agent não instalado ou sudoers ausente — rode o bootstrap na VM";

    public string HostKeySha256 { get; } = hostKeySha256;

    public async Task<CommandResult> RunAgentAsync(string subcommand, IReadOnlyList<string> args, Action<string>? onLine, TimeSpan timeout, CancellationToken ct)
    {
        var text = ShellQuote.BuildAgentCommand(subcommand, args);
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
            await cmd.ExecuteAsync(cts.Token).ConfigureAwait(false);
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
        if (LooksLikeMissingAgent(exit, se)) throw new TargetException(NotInstalledMessage);
        return new CommandResult(exit, so, se);
    }

    public static bool LooksLikeMissingAgent(int exit, string stderr) =>
        stderr.Contains("sudo: a password is required", StringComparison.Ordinal)
        || stderr.Contains("sudo: a terminal is required", StringComparison.Ordinal)
        || (exit == 1 && stderr.Contains("is not in the sudoers", StringComparison.Ordinal))
        || (exit is 127 or 1 && stderr.Contains("command not found", StringComparison.OrdinalIgnoreCase))
        || (exit == 127 && stderr.Contains("not found", StringComparison.OrdinalIgnoreCase));

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
