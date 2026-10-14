using PvePatcher.Targets;

namespace PvePatcher.Web.Services;

/// <summary>Bootstrap real: script e comando vêm do módulo Targets (patcher-agent embutido como recurso).</summary>
public sealed class TargetsBootstrapScriptProvider : IBootstrapScriptProvider
{
    private readonly Lazy<string> _script = new(BootstrapScript.Render);

    public string Render() => _script.Value;

    public string Command(string url, string publicKey, string user, string? fromCidr) =>
        BootstrapScript.Command(url, publicKey, user, fromCidr);
}
