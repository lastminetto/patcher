namespace PvePatcher.Integrations.OpenBao;

/// <summary>Seção "OpenBao" do appsettings.</summary>
public sealed class OpenBaoOptions
{
    public const string Section = "OpenBao";

    public string Address { get; set; } = "http://127.0.0.1:8200";
    public string KvMount { get; set; } = "pve-patcher";
    public string RoleIdFile { get; set; } = "/etc/pve-patcher/approle/role_id";
    public string SecretIdFile { get; set; } = "/etc/pve-patcher/approle/secret_id";

    /// <summary>Por quanto tempo uma leitura fica em memória.</summary>
    public TimeSpan CacheTtl { get; set; } = TimeSpan.FromSeconds(60);
}
