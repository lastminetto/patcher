namespace PvePatcher.Targets;

/// <summary>
/// Gera o bootstrap-vm.sh auto-contido (com o patcher-upgrade embutido no lugar do marcador): cria o usuário
/// restrito, autoriza a chave do app e grava o sudoers com os comandos fixos de update/upgrade/reboot.
/// </summary>
public static class BootstrapScript
{
    public const string Placeholder = "@@PATCHER_UPGRADE@@";
    public const string Terminator = "PATCHER_UPGRADE_EOF";

    public static string Build(string template, string wrapper)
    {
        var w = wrapper.Replace("\r\n", "\n").TrimEnd('\n');
        if (w.Split('\n').Any(l => l == Terminator))
            throw new ArgumentException($"O wrapper não pode conter a linha {Terminator}");
        return template.Replace("\r\n", "\n").Replace(Placeholder + "\n", w + "\n");
    }

    /// <summary>Script pronto a partir dos recursos embutidos no assembly.</summary>
    public static string Render() => Build(ReadResource("bootstrap-vm.sh"), ReadResource("patcher-upgrade"));

    /// <summary>
    /// bootstrap-console.sh: confere e ajusta a conta do terminal (chave sem no-pty, permissões, sudo NOPASSWD).
    /// O comando é o mesmo formato de <see cref="Command"/>, sem <c>--from</c>.
    /// </summary>
    public static string RenderConsole() => ReadResource("bootstrap-console.sh").Replace("\r\n", "\n");

    /// <summary>
    /// Comando para o usuário colar na VM, como root. <paramref name="scriptUrl"/> é onde a UI serve o resultado de <see cref="Render"/>.
    /// Com <paramref name="pinSha256"/> (certificado autoassinado do app) o curl aceita a cadeia (<c>-k</c>) mas exige a chave pinada.
    /// </summary>
    public static string Command(string scriptUrl, string publicKey, string user = "patcher", string? fromCidr = null, string? pinSha256 = null)
    {
        var curl = string.IsNullOrWhiteSpace(pinSha256)
            ? "curl -fsSL"
            : $"curl -fsSLk --pinnedpubkey {ShellQuote.Quote("sha256//" + pinSha256)}";
        var cmd = $"{curl} {ShellQuote.Quote(scriptUrl)} | sh -s -- --pubkey {ShellQuote.Quote(publicKey.Trim())} --user {ShellQuote.Quote(user)}";
        return string.IsNullOrWhiteSpace(fromCidr) ? cmd : cmd + $" --from {ShellQuote.Quote(fromCidr)}";
    }

    internal static string ReadResource(string name)
    {
        using var s = typeof(BootstrapScript).Assembly.GetManifestResourceStream("PvePatcher.Targets.deploy." + name)
            ?? throw new InvalidOperationException($"Recurso {name} ausente");
        using var r = new StreamReader(s);
        return r.ReadToEnd();
    }
}
