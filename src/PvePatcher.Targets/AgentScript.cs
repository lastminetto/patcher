namespace PvePatcher.Targets;

/// <summary>O patcher-agent embutido no assembly, enviado pelo stdin a cada execução (nada é gravado na VM).</summary>
public static class AgentScript
{
    private static readonly Lazy<string> Cached = new(Load);

    /// <summary>Texto do script com fins de linha LF.</summary>
    public static string Text => Cached.Value;

    private static string Load()
    {
        using var s = typeof(AgentScript).Assembly.GetManifestResourceStream("PvePatcher.Targets.deploy.patcher-agent")
            ?? throw new InvalidOperationException("Recurso patcher-agent ausente");
        using var r = new StreamReader(s);
        return r.ReadToEnd().Replace("\r\n", "\n");
    }
}
