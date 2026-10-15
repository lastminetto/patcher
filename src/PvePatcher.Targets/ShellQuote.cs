namespace PvePatcher.Targets;

public static class ShellQuote
{
    /// <summary>Aspas simples POSIX: ' vira '\'' . Sempre cita, mesmo valores simples.</summary>
    public static string Quote(string value) => "'" + value.Replace("'", "'\\''") + "'";

    /// <summary>
    /// Comando remoto do modo sem agente: o patcher-agent vai pelo stdin do canal SSH e roda em <c>sh -s</c>.
    /// Root executa direto; qualquer outro usuário precisa de sudo sem senha (<c>sudo -n</c>).
    /// </summary>
    public static string BuildAgentCommand(string subcommand, IReadOnlyList<string> args, string user)
    {
        var parts = new List<string>();
        if (!string.Equals(user, "root", StringComparison.Ordinal)) parts.AddRange(["sudo", "-n"]);
        parts.AddRange(["sh", "-s", "--", Quote(subcommand)]);
        parts.AddRange(args.Select(Quote));
        return string.Join(' ', parts);
    }
}
