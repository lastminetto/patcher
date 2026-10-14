namespace PvePatcher.Targets;

/// <summary>Seção "Ssh" da configuração.</summary>
public sealed class SshOptions
{
    public int ConnectTimeoutSeconds { get; set; } = 15;
    public int KeepAliveSeconds { get; set; } = 30;
    public int RefreshTimeoutMinutes { get; set; } = 10;
    public int UpgradeTimeoutMinutes { get; set; } = 60;
    public int QueryTimeoutSeconds { get; set; } = 120;
}
