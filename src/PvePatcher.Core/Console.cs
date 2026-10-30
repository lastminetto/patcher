namespace PvePatcher.Core;

/// <summary>Shell interativo (PTY xterm-256color) aberto pelo terminal da UI.</summary>
public interface IShellSession : IAsyncDisposable
{
    /// <summary>Impressão da host key apresentada ("SHA256:...").</summary>
    string HostKeySha256 { get; }

    /// <summary>Lê a saída do shell; 0 = sessão encerrada.</summary>
    ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct);

    ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken ct);

    /// <summary>Novo tamanho do terminal (colunas x linhas).</summary>
    void Resize(int cols, int rows);
}

/// <param name="Mode">Permissões no formato do ls ("drwxr-xr-x").</param>
public sealed record SftpEntry(string Name, string Path, bool IsDirectory, bool IsSymlink, long Size, DateTimeOffset ModifiedUtc, string Mode);

/// <summary>Sessão SFTP com o usuário do terminal (as permissões são as dele na VM).</summary>
public interface ISftpSession : IAsyncDisposable
{
    string HostKeySha256 { get; }

    /// <summary>Diretório inicial (home do usuário).</summary>
    string Home { get; }

    Task<IReadOnlyList<SftpEntry>> ListAsync(string path, CancellationToken ct);

    Task<SftpEntry> StatAsync(string path, CancellationToken ct);

    Task DownloadAsync(string path, Stream destination, CancellationToken ct);

    Task UploadAsync(Stream source, string path, bool overwrite, CancellationToken ct);

    Task CreateDirectoryAsync(string path, CancellationToken ct);

    Task RenameAsync(string from, string to, CancellationToken ct);

    /// <summary>Apaga arquivo, link ou diretório vazio.</summary>
    Task DeleteAsync(string path, CancellationToken ct);
}

/// <summary>Abre shells e sessões SFTP para o terminal (mesma checagem de host key do <see cref="ITargetConnector"/>).</summary>
public interface IConsoleConnector
{
    /// <summary>Lança <see cref="HostKeyMismatchException"/> se a host key não bater com a conhecida.</summary>
    Task<IShellSession> OpenShellAsync(SshTarget target, int cols, int rows, CancellationToken ct);

    /// <summary>Lança <see cref="HostKeyMismatchException"/> se a host key não bater com a conhecida.</summary>
    Task<ISftpSession> OpenSftpAsync(SshTarget target, CancellationToken ct);
}
