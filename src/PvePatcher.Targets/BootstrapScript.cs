namespace PvePatcher.Targets;

/// <summary>Gera o bootstrap-vm.sh auto-contido (com o patcher-agent embutido no lugar do marcador).</summary>
public static class BootstrapScript
{
    public const string Placeholder = "@@PATCHER_AGENT@@";

    public static string Build(string template, string agent)
    {
        var a = agent.Replace("\r\n", "\n").TrimEnd('\n');
        if (a.Split('\n').Any(l => l == "PATCHER_AGENT_EOF"))
            throw new ArgumentException("O agent não pode conter a linha PATCHER_AGENT_EOF");
        return template.Replace("\r\n", "\n").Replace(Placeholder + "\n", a + "\n");
    }

    /// <summary>Script pronto a partir dos recursos embutidos no assembly.</summary>
    public static string Render() => Build(ReadResource("bootstrap-vm.sh"), ReadResource("patcher-agent"));

    /// <summary>
    /// Comando para o usuário colar na VM, como root. <paramref name="scriptUrl"/> é onde a UI serve o resultado de <see cref="Render"/>.
    /// </summary>
    public static string Command(string scriptUrl, string publicKey, string user = "patcher", string? fromCidr = null)
    {
        var cmd = $"curl -fsSL {ShellQuote.Quote(scriptUrl)} | sh -s -- --pubkey {ShellQuote.Quote(publicKey)} --user {ShellQuote.Quote(user)}";
        return fromCidr is null ? cmd : cmd + $" --from {ShellQuote.Quote(fromCidr)}";
    }

    private static string ReadResource(string name)
    {
        using var s = typeof(BootstrapScript).Assembly.GetManifestResourceStream("PvePatcher.Targets.deploy." + name)
            ?? throw new InvalidOperationException($"Recurso {name} ausente");
        using var r = new StreamReader(s);
        return r.ReadToEnd();
    }
}
