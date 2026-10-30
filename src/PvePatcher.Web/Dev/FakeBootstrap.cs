namespace PvePatcher.Web.Dev;

/// <summary>Só para desenvolvimento: devolve um script de exemplo e o comando no formato esperado.</summary>
public sealed class FakeBootstrapScriptProvider : IBootstrapScriptProvider
{
    public string Render() => "#!/bin/sh\n# script de bootstrap FAKE (Dev:UseFakes)\necho 'bootstrap fake: nada foi feito'\n";

    public string RenderConsole() => "#!/bin/sh\n# bootstrap do terminal FAKE (Dev:UseFakes)\necho 'bootstrap-console fake: nada foi feito'\n";

    public string Command(string url, string publicKey, string user, string? fromCidr, string? pinSha256)
    {
        var curl = pinSha256 is null ? "curl -fsSL" : $"curl -fsSLk --pinnedpubkey 'sha256//{pinSha256}'";
        var cmd = $"{curl} '{url}' | sh -s -- --pubkey '{publicKey.Replace("'", "").Trim()}' --user '{user}'";
        if (!string.IsNullOrWhiteSpace(fromCidr)) cmd += $" --from '{fromCidr}'";
        return cmd;
    }
}
