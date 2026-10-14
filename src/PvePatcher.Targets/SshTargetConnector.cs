using System.Text;
using Microsoft.Extensions.Options;
using PvePatcher.Core;
using Renci.SshNet;

namespace PvePatcher.Targets;

public sealed class SshTargetConnector(IOptions<SshOptions> options) : ITargetConnector
{
    private readonly SshOptions _options = options.Value;

    public async Task<ITargetSession> ConnectAsync(SshTarget target, CancellationToken ct)
    {
        PrivateKeyFile keyFile;
        try
        {
            using var ms = new MemoryStream(Encoding.UTF8.GetBytes(NormalizeKey(target.PrivateKey)));
            keyFile = string.IsNullOrEmpty(target.Passphrase) ? new PrivateKeyFile(ms) : new PrivateKeyFile(ms, target.Passphrase);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new TargetException($"Chave privada inválida ou passphrase incorreta: {ex.Message}", ex);
        }

        var info = new ConnectionInfo(target.Host, target.Port, target.User, new PrivateKeyAuthenticationMethod(target.User, keyFile))
        {
            Timeout = TimeSpan.FromSeconds(_options.ConnectTimeoutSeconds),
        };
        var client = new SshClient(info) { KeepAliveInterval = TimeSpan.FromSeconds(_options.KeepAliveSeconds) };

        string? fingerprint = null;
        client.HostKeyReceived += (_, e) =>
        {
            fingerprint = HostKeyFingerprint.Sha256(e.HostKey);
            e.CanTrust = target.KnownHostKeySha256 is null
                || string.Equals(target.KnownHostKeySha256, fingerprint, StringComparison.Ordinal);
        };

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(_options.ConnectTimeoutSeconds));
            await client.ConnectAsync(cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            client.Dispose();
            if (ct.IsCancellationRequested) throw new OperationCanceledException(ct);
            if (fingerprint is not null && target.KnownHostKeySha256 is not null && fingerprint != target.KnownHostKeySha256)
                throw new HostKeyMismatchException(target.KnownHostKeySha256, fingerprint);
            var reason = ex is OperationCanceledException ? "tempo esgotado" : ex.Message;
            throw new TargetException($"Falha ao conectar em {target.Host}:{target.Port} como {target.User}: {reason}", ex);
        }

        return new SshTargetSession(client, fingerprint ?? "");
    }

    // Chaves coladas de formulários costumam vir com CRLF ou sem newline final.
    private static string NormalizeKey(string key) => key.Replace("\r\n", "\n").Trim() + "\n";
}
