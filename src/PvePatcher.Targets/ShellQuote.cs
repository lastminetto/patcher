namespace PvePatcher.Targets;

public static class ShellQuote
{
    public const string AgentPath = "/usr/local/sbin/patcher-agent";

    /// <summary>Aspas simples POSIX: ' vira '\'' . Sempre cita, mesmo valores simples.</summary>
    public static string Quote(string value) => "'" + value.Replace("'", "'\\''") + "'";

    public static string BuildAgentCommand(string subcommand, IReadOnlyList<string> args)
    {
        var parts = new List<string> { "sudo", "-n", AgentPath, Quote(subcommand) };
        parts.AddRange(args.Select(Quote));
        return string.Join(' ', parts);
    }
}
