using PvePatcher.Core;

namespace PvePatcher.Web.Services;

/// <summary>Escrita de segredos no cofre pela UI. Os valores nunca são lidos de volta (exceto a chave pública).</summary>
public sealed class SecretsService(ISecretStore vault, SettingsService settings, TimeProvider time)
{
    public const string MarkSsh = "ssh/default";
    public const string MarkConsole = "ssh/console";
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

    public Task SetSshKeyAsync(string privateKey, string? publicKey, string? passphrase, CancellationToken ct) =>
        SetKeyAsync(SecretPaths.SshDefault, MarkSsh, privateKey, publicKey, passphrase, null, ct);

    /// <summary>Gera um par ed25519, grava no cofre e devolve só a pública.</summary>
    public async Task<string> GenerateSshKeyAsync(CancellationToken ct)
    {
        var kp = Ed25519OpenSsh.Generate("pve-patcher");
        await SetSshKeyAsync(kp.PrivateKey, kp.PublicKey, null, ct);
        return kp.PublicKey;
    }

    /// <summary>
    /// Chave exclusiva do terminal (ssh/console), com certificado OpenSSH opcional. Antes de gravar confere que a chave
    /// abre com a passphrase e que o certificado é desta chave (<see cref="ArgumentException"/> com o motivo).
    /// </summary>
    public async Task SetConsoleKeyAsync(string privateKey, string? publicKey, string? passphrase, string? certificate, CancellationToken ct)
    {
        try { PvePatcher.Targets.SshConnect.LoadKey(privateKey, passphrase, certificate); }
        catch (TargetException ex) { throw new ArgumentException(ex.Message, ex); }
        await SetKeyAsync(SecretPaths.SshConsole, MarkConsole, privateKey, publicKey, passphrase, certificate, ct);
    }

    public async Task<string> GenerateConsoleKeyAsync(CancellationToken ct)
    {
        var kp = Ed25519OpenSsh.Generate("pve-patcher-console");
        await SetKeyAsync(SecretPaths.SshConsole, MarkConsole, kp.PrivateKey, kp.PublicKey, null, null, ct);
        return kp.PublicKey;
    }

    private async Task SetKeyAsync(string path, string mark, string privateKey, string? publicKey, string? passphrase, string? certificate, CancellationToken ct)
    {
        var data = new Dictionary<string, string> { [SecretPaths.PrivateKey] = privateKey.Replace("\r\n", "\n").TrimEnd() + "\n" };
        if (!string.IsNullOrWhiteSpace(publicKey)) data[SecretPaths.PublicKey] = publicKey.Trim();
        if (!string.IsNullOrEmpty(passphrase)) data[SecretPaths.Passphrase] = passphrase;
        if (!string.IsNullOrWhiteSpace(certificate)) data[SecretPaths.Certificate] = certificate.Trim();
        await vault.WriteAsync(path, data, ct);
        await settings.MarkSecretAsync(mark, time.GetUtcNow());
    }

    /// <summary>Se o segredo existe (sem expor o valor). Null se o cofre não responde.</summary>
    public async Task<bool?> ExistsAsync(string path, CancellationToken ct)
    {
        try { return await vault.ReadAsync(path, ct) is not null; }
        catch (VaultUnavailableException) { return null; }
    }

    /// <summary>Chave pública da chave SSH padrão (null se não houver ou o cofre não responder).</summary>
    public Task<string?> GetSshPublicKeyAsync(CancellationToken ct) => GetPublicAsync(SecretPaths.SshDefault, ct);

    /// <summary>Chave pública e se há certificado, da chave do terminal (null se não houver ou o cofre não responder).</summary>
    public async Task<(string? PublicKey, bool HasCertificate)?> GetConsoleKeyInfoAsync(CancellationToken ct)
    {
        try
        {
            var d = await vault.ReadAsync(SecretPaths.SshConsole, ct);
            if (d is null) return null;
            return (d.TryGetValue(SecretPaths.PublicKey, out var p) ? p : null, d.ContainsKey(SecretPaths.Certificate));
        }
        catch (VaultUnavailableException) { return null; }
    }

    private async Task<string?> GetPublicAsync(string path, CancellationToken ct)
    {
        try
        {
            var d = await vault.ReadAsync(path, ct);
            return d is not null && d.TryGetValue(SecretPaths.PublicKey, out var p) ? p : null;
        }
        catch (VaultUnavailableException) { return null; }
    }
}

/// <summary>Script de bootstrap das VMs (implementação real: PvePatcher.Targets.BootstrapScript, ligada na composição).</summary>
public interface IBootstrapScriptProvider
{
    /// <summary>bootstrap-vm.sh com o patcher-upgrade embutido.</summary>
    string Render();

    /// <summary>bootstrap-console.sh: confere e ajusta a conta do terminal (chave, permissões, sudo sem senha).</summary>
    string RenderConsole();

    /// <summary>Comando de uma linha para rodar como root na VM.</summary>
    string Command(string url, string publicKey, string user, string? fromCidr, string? pinSha256);
}
