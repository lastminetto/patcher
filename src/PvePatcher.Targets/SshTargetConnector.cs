using Microsoft.Extensions.Options;
using PvePatcher.Core;
using Renci.SshNet;

namespace PvePatcher.Targets;

public sealed class SshTargetConnector(IOptions<SshOptions> options) : ITargetConnector
{
    private readonly SshOptions _options = options.Value;

    public async Task<ITargetSession> ConnectAsync(SshTarget target, CancellationToken ct)
    {
        var (client, fingerprint) = await SshConnect.ConnectAsync(target, _options, info => new SshClient(info), ct).ConfigureAwait(false);
        return new SshTargetSession(client, fingerprint);
    }
}
