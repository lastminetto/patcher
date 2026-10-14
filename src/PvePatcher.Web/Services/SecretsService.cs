using PvePatcher.Core;

namespace PvePatcher.Web.Services;

/// <summary>Escrita de segredos no cofre pela UI. Os valores nunca são lidos de volta (exceto a chave pública).</summary>
public sealed class SecretsService(ISecretStore vault, SettingsService settings, TimeProvider time)
{
    public const string MarkSsh = "ssh/default";
    public const string MarkNvd = "feeds/nvd";
    public static string MarkCluster(string id) => $"cluster/{id}";

    public async Task SetClusterTokenAsync(string clusterId, string tokenId, string tokenSecret, CancellationToken ct)
    {
        await vault.WriteAsync(SecretPaths.Cluster(clusterId), new Dictionary<string, string>
        {
            [SecretPaths.TokenId] = tokenId.Trim(),
            [SecretPaths.TokenSecret] = tokenSecret.Trim(),
        }, ct);
        await settings.MarkSecretAsync(MarkCluster(clusterId), time.GetUtcNow());
    }

    public async Task DeleteClusterTokenAsync(string clusterId, CancellationToken ct)
    {
        await vault.DeleteAsync(SecretPaths.Cluster(clusterId), ct);
        var s = settings.Current;
        s.SecretsSetAt.Remove(MarkCluster(clusterId));
        await settings.SaveAsync(s);
    }

    public async Task SetNvdKeyAsync(string apiKey, CancellationToken ct)
    {
        await vault.WriteAsync(SecretPaths.Nvd, new Dictionary<string, string> { [SecretPaths.ApiKey] = apiKey.Trim() }, ct);
        await settings.MarkSecretAsync(MarkNvd, time.GetUtcNow());
    }

    public async Task SetSshKeyAsync(string privateKey, string? publicKey, string? passphrase, CancellationToken ct)
    {
        var data = new Dictionary<string, string> { [SecretPaths.PrivateKey] = privateKey.Replace("\r\n", "\n").TrimEnd() + "\n" };
        if (!string.IsNullOrWhiteSpace(publicKey)) data[SecretPaths.PublicKey] = publicKey.Trim();
        if (!string.IsNullOrEmpty(passphrase)) data[SecretPaths.Passphrase] = passphrase;
        await vault.WriteAsync(SecretPaths.SshDefault, data, ct);
        await settings.MarkSecretAsync(MarkSsh, time.GetUtcNow());
    }

    /// <summary>Gera um par ed25519, grava no cofre e devolve só a pública.</summary>
    public async Task<string> GenerateSshKeyAsync(CancellationToken ct)
    {
        var kp = Ed25519OpenSsh.Generate("pve-patcher");
        await SetSshKeyAsync(kp.PrivateKey, kp.PublicKey, null, ct);
        return kp.PublicKey;
    }

    /// <summary>Se o segredo existe (sem expor o valor). Null se o cofre não responde.</summary>
    public async Task<bool?> ExistsAsync(string path, CancellationToken ct)
    {
        try { return await vault.ReadAsync(path, ct) is not null; }
        catch (VaultUnavailableException) { return null; }
    }

    /// <summary>Chave pública da chave SSH padrão (null se não houver ou o cofre não responder).</summary>
    public async Task<string?> GetSshPublicKeyAsync(CancellationToken ct)
    {
        try
        {
            var d = await vault.ReadAsync(SecretPaths.SshDefault, ct);
            return d is not null && d.TryGetValue(SecretPaths.PublicKey, out var p) ? p : null;
        }
        catch (VaultUnavailableException) { return null; }
    }
}

/// <summary>Script de bootstrap das VMs (implementação real: PvePatcher.Targets.BootstrapScript, ligada na composição).</summary>
public interface IBootstrapScriptProvider
{
    /// <summary>bootstrap-vm.sh com o patcher-agent embutido.</summary>
    string Render();

    /// <summary>Comando de uma linha para rodar como root na VM.</summary>
    string Command(string url, string publicKey, string user, string? fromCidr);
}
