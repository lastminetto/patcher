using System.Text;
using PvePatcher.Core;
using Renci.SshNet;

namespace PvePatcher.Targets;

/// <summary>Conexão SSH comum ao patcher e ao terminal: chave (+ certificado OpenSSH), timeouts e checagem da host key.</summary>
public static class SshConnect
{
    /// <summary>Carrega a chave privada (e o certificado, se houver). Lança <see cref="TargetException"/> com mensagem legível.</summary>
    public static PrivateKeyFile LoadKey(string privateKey, string? passphrase, string? certificate)
    {
        try
        {
            using var key = new MemoryStream(Encoding.UTF8.GetBytes(NormalizeKey(privateKey)));
            if (!string.IsNullOrWhiteSpace(certificate))
            {
                using var cert = new MemoryStream(Encoding.UTF8.GetBytes(certificate.Trim() + "\n"));
                return new PrivateKeyFile(key, string.IsNullOrEmpty(passphrase) ? null : passphrase, cert);
            }
            return string.IsNullOrEmpty(passphrase) ? new PrivateKeyFile(key) : new PrivateKeyFile(key, passphrase);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var what = string.IsNullOrWhiteSpace(certificate) ? "Chave privada inválida ou passphrase incorreta" : "Chave privada, passphrase ou certificado inválidos";
            throw new TargetException($"{what}: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Conecta um cliente SSH.NET (<see cref="SshClient"/> ou <see cref="SftpClient"/>) e devolve a impressão da host key.
    /// Lança <see cref="HostKeyMismatchException"/> se a host key não bater com <see cref="SshTarget.KnownHostKeySha256"/>.
    /// </summary>
    public static async Task<(TClient Client, string HostKeySha256)> ConnectAsync<TClient>(
        SshTarget target, SshOptions options, Func<ConnectionInfo, TClient> factory, CancellationToken ct)
        where TClient : BaseClient
    {
        var keyFile = LoadKey(target.PrivateKey, target.Passphrase, target.Certificate);
        var info = new ConnectionInfo(target.Host, target.Port, target.User, new PrivateKeyAuthenticationMethod(target.User, keyFile))
        {
            Timeout = TimeSpan.FromSeconds(options.ConnectTimeoutSeconds),
        };
        var client = factory(info);
        client.KeepAliveInterval = TimeSpan.FromSeconds(options.KeepAliveSeconds);

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
            cts.CancelAfter(TimeSpan.FromSeconds(options.ConnectTimeoutSeconds));
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

        return (client, fingerprint ?? "");
    }

    // Chaves coladas de formulários costumam vir com CRLF ou sem newline final.
    private static string NormalizeKey(string key) => key.Replace("\r\n", "\n").Trim() + "\n";
}
