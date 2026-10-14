namespace PvePatcher.Web.Dev;

/// <summary>Só para desenvolvimento: devolve um script de exemplo e o comando no formato esperado.</summary>
public sealed class FakeBootstrapScriptProvider : IBootstrapScriptProvider
{
    public string Render() => "#!/bin/sh\n# script de bootstrap FAKE (Dev:UseFakes)\necho 'bootstrap fake: nada foi feito'\n";

    public string Command(string url, string publicKey, string user, string? fromCidr)
    {
        var cmd = $"curl -fsSL {url} | sh -s -- --pubkey '{publicKey.Replace("'", "").Trim()}'";
        if (!string.IsNullOrWhiteSpace(user) && user != "patcher") cmd += $" --user {user}";
        if (!string.IsNullOrWhiteSpace(fromCidr)) cmd += $" --from {fromCidr}";
        return cmd;
    }
}
