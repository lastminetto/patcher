namespace PvePatcher.Core;

/// <param name="KnownHostKeySha256">Impressão gravada (formato "SHA256:base64" do OpenSSH). Null = TOFU.</param>
public sealed record SshTarget(
    string Host,
    int Port,
    string User,
    string PrivateKey,
    string? Passphrase,
    string? KnownHostKeySha256);

public sealed record CommandResult(int ExitCode, string StdOut, string StdErr);


/// <summary>Sessão SSH aberta em uma VM. Executa o patcher-agent (enviado pelo stdin a cada execução; nada fica instalado na VM).</summary>
public interface ITargetSession : IAsyncDisposable
{
    /// <summary>Impressão da host key apresentada ("SHA256:...").</summary>
    string HostKeySha256 { get; }

    /// <summary>
    /// Roda "[sudo -n] sh -s -- &lt;subcommand&gt; [args]" com o script do agente no stdin (sudo só se o usuário não for root). Cada linha de stdout/stderr
    /// é entregue a <paramref name="onLine"/> conforme chega (log ao vivo).
    /// </summary>
    Task<CommandResult> RunAgentAsync(string subcommand, IReadOnlyList<string> args, Action<string>? onLine, TimeSpan timeout, CancellationToken ct);
}

public interface ITargetConnector
{
    /// <summary>Lança <see cref="HostKeyMismatchException"/> se a host key não bater com a conhecida.</summary>
    Task<ITargetSession> ConnectAsync(SshTarget target, CancellationToken ct);
}

public class HostKeyMismatchException(string expected, string actual)
    : Exception($"Host key mudou: esperado {expected}, recebido {actual}")
{
    public string Expected { get; } = expected;
    public string Actual { get; } = actual;
}

/// <summary>Erro de execução do patcher-agent (exit != 0, sudo sem NOPASSWD ou com requiretty...).</summary>
public class TargetException(string message, Exception? inner = null) : Exception(message, inner);

/// <param name="SourceName">Pacote-fonte (dpkg ${source:Package}, SOURCERPM sem versão, apk origin).</param>
/// <param name="SourceVersion">Versão do fonte quando difere da binária (Debian binNMU); senão igual a Version.</param>
public sealed record InstalledPackage(string Name, string SourceName, string Version, string SourceVersion, string? Arch);

/// <param name="HeldBack">apt: candidata existe mas "apt-get upgrade" não instala (dependência nova).</param>
public sealed record PendingUpdate(string Name, string SourceName, string InstalledVersion, string CandidateVersion, string? Arch, bool HeldBack);

public sealed record HostScan(
    OsInfo Os,
    string Kernel,
    IReadOnlyList<InstalledPackage> Installed,
    IReadOnlyList<PendingUpdate> Pending,
    bool RebootRequired,
    DateTimeOffset ScannedAt);

public interface IHostScanner
{
    /// <summary>refresh (apt-get update / dnf makecache / apk update) + list + reboot-required.</summary>
    Task<HostScan> ScanAsync(ITargetSession session, Action<string>? onLine, CancellationToken ct);
}

public enum UpgradeMode
{
    /// <summary>apt-get upgrade / dnf upgrade / apk upgrade.</summary>
    All,
    /// <summary>Só os pacotes informados (os que corrigem CVE).</summary>
    Packages,
}

public sealed record UpgradeOutcome(bool Success, int ExitCode, bool RebootRequired);

public interface IHostUpdater
{
    Task<UpgradeOutcome> UpgradeAsync(ITargetSession session, UpgradeMode mode, IReadOnlyList<string> packages, Action<string>? onLine, CancellationToken ct);

    Task<bool> RebootRequiredAsync(ITargetSession session, CancellationToken ct);

    /// <summary>Dispara o reboot e retorna (a conexão cai em seguida).</summary>
    Task RebootAsync(ITargetSession session, CancellationToken ct);
}
