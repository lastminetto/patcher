using PvePatcher.Targets;

namespace PvePatcher.Web.Services;

/// <summary>Bootstrap real: script e comando vêm do módulo Targets (patcher-upgrade embutido como recurso).</summary>
public sealed class TargetsBootstrapScriptProvider : IBootstrapScriptProvider
{
    private readonly Lazy<string> _script = new(BootstrapScript.Render);
    private readonly Lazy<string> _console = new(BootstrapScript.RenderConsole);

    public string Render() => _script.Value;

    public string RenderConsole() => _console.Value;

    public string Command(string url, string publicKey, string user, string? fromCidr, string? pinSha256) =>
        BootstrapScript.Command(url, publicKey, user, fromCidr, pinSha256);
}
