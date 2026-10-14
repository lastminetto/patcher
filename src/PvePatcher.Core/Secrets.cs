namespace PvePatcher.Core;

public enum VaultState { Ready, Sealed, Unreachable, AuthFailed }

public sealed record VaultStatus(VaultState State, string? Detail);

/// <summary>
/// Cofre (OpenBao KV v2). Caminhos são relativos ao mount configurado.
/// Lança <see cref="VaultUnavailableException"/> quando selado/inacessível.
/// </summary>
public interface ISecretStore
{
    Task<VaultStatus> GetStatusAsync(CancellationToken ct);

    /// <summary>Null se o caminho não existe.</summary>
    Task<IReadOnlyDictionary<string, string>?> ReadAsync(string path, CancellationToken ct);

    Task WriteAsync(string path, IReadOnlyDictionary<string, string> data, CancellationToken ct);

    Task DeleteAsync(string path, CancellationToken ct);
}

public class VaultUnavailableException(VaultStatus status)
    : Exception($"Cofre indisponível: {status.State} {status.Detail}")
{
    public VaultStatus Status { get; } = status;
}

/// <summary>Layout dos segredos no KV. Todos os módulos usam estes caminhos/chaves.</summary>
public static class SecretPaths
{
    /// <summary>Chaves: token_id ("user@realm!nome"), token_secret.</summary>
    public static string Cluster(string clusterId) => $"pve/clusters/{clusterId}";
    public const string TokenId = "token_id";
    public const string TokenSecret = "token_secret";

    /// <summary>Chave SSH padrão. Chaves: private_key (OpenSSH/PEM), public_key, passphrase (opcional).</summary>
    public const string SshDefault = "ssh/default";
    /// <summary>Override por VM, mesmas chaves de SshDefault (+ user opcional).</summary>
    public static string SshVm(string clusterId, int vmId) => $"ssh/vm/{clusterId}/{vmId}";
    public const string PrivateKey = "private_key";
    public const string PublicKey = "public_key";
    public const string Passphrase = "passphrase";
    public const string User = "user";

    /// <summary>Chave: api_key.</summary>
    public const string Nvd = "feeds/nvd";
    public const string ApiKey = "api_key";
}
