namespace PvePatcher.Targets;

public static class ShellQuote
{
    /// <summary>Aspas simples POSIX: ' vira '\'' . Sempre cita, mesmo valores simples.</summary>
    public static string Quote(string value) => "'" + value.Replace("'", "'\\''") + "'";

    /// <summary>
    /// Comando remoto do modo sem agente: o patcher-agent vai pelo stdin do canal SSH e roda em <c>sh -s</c>
    /// com o próprio usuário da conexão. Sem root, o agente usa <c>sudo -n</c> só nos passos privilegiados
    /// (os comandos que o sudoers do bootstrap libera).
    /// </summary>
    public static string BuildAgentCommand(string subcommand, IReadOnlyList<string> args)
    {
        var parts = new List<string> { "sh", "-s", "--", Quote(subcommand) };
        parts.AddRange(args.Select(Quote));
        return string.Join(' ', parts);
    }
}
