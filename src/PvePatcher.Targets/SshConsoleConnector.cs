using System.Threading.Channels;
using Microsoft.Extensions.Options;
using PvePatcher.Core;
using Renci.SshNet;
using Renci.SshNet.Sftp;

namespace PvePatcher.Targets;

/// <summary>Shell (PTY xterm-256color) e SFTP para o terminal da UI.</summary>
public sealed class SshConsoleConnector(IOptions<SshOptions> options) : IConsoleConnector
{
    private readonly SshOptions _options = options.Value;

    public async Task<IShellSession> OpenShellAsync(SshTarget target, int cols, int rows, CancellationToken ct)
    {
        var (client, fingerprint) = await SshConnect.ConnectAsync(target, _options, info => new SshClient(info), ct).ConfigureAwait(false);
        try
        {
            var stream = client.CreateShellStream("xterm-256color", (uint)Math.Max(cols, 1), (uint)Math.Max(rows, 1), 0, 0, 64 * 1024);
            return new SshShellSession(client, stream, fingerprint);
        }
        catch (Exception ex)
        {
            client.Dispose();
            throw new TargetException($"O servidor recusou o shell interativo: {ex.Message}", ex);
        }
    }

    public async Task<ISftpSession> OpenSftpAsync(SshTarget target, CancellationToken ct)
    {
        var (client, fingerprint) = await SshConnect.ConnectAsync(target, _options, info => new SftpClient(info), ct).ConfigureAwait(false);
        return new SshSftpSession(client, fingerprint);
    }
}

/// <summary>
/// O ShellStream só tem Read bloqueante: uma thread dedicada por sessão lê e entrega pedaços num canal
/// limitado (contrapressão), sem prender threads do pool.
/// </summary>
public sealed class SshShellSession : IShellSession
{
    private readonly SshClient _client;
    private readonly ShellStream _stream;
    private readonly Channel<byte[]> _out = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(64) { SingleReader = true, SingleWriter = true });
    private readonly Lock _writeGate = new();
    private byte[]? _pending;
    private int _pendingOffset;
    private int _disposed;

    public SshShellSession(SshClient client, ShellStream stream, string hostKeySha256)
    {
        _client = client;
        _stream = stream;
        HostKeySha256 = hostKeySha256;
        new Thread(Pump) { IsBackground = true, Name = "ssh-shell-reader" }.Start();
    }

    public string HostKeySha256 { get; }

    private void Pump()
    {
        var buf = new byte[16 * 1024];
        try
        {
            while (true)
            {
                var n = _stream.Read(buf, 0, buf.Length);
                if (n <= 0) break;
                var chunk = buf.AsSpan(0, n).ToArray();
                // Bloqueia se o navegador não estiver consumindo (canal cheio).
                while (!_out.Writer.TryWrite(chunk))
                {
                    if (!_out.Writer.WaitToWriteAsync().AsTask().GetAwaiter().GetResult()) return;
                }
            }
        }
        catch (Exception) when (Volatile.Read(ref _disposed) == 1) { /* fechado por nós */ }
        catch (Exception ex) { _out.Writer.TryComplete(ex); return; }
        _out.Writer.TryComplete();
    }

    public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct)
    {
        if (_pending is null)
        {
            if (!await _out.Reader.WaitToReadAsync(ct).ConfigureAwait(false)) return 0;
            if (!_out.Reader.TryRead(out _pending)) return 0;
            _pendingOffset = 0;
        }
        var n = Math.Min(buffer.Length, _pending.Length - _pendingOffset);
        _pending.AsMemory(_pendingOffset, n).CopyTo(buffer);
        _pendingOffset += n;
        if (_pendingOffset >= _pending.Length) _pending = null;
        return n;
    }

    public ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken ct)
    {
        lock (_writeGate)
        {
            _stream.Write(data.Span);
            _stream.Flush();
        }
        return ValueTask.CompletedTask;
    }

    public void Resize(int cols, int rows) =>
        _stream.ChangeWindowSize((uint)Math.Clamp(cols, 1, 1000), (uint)Math.Clamp(rows, 1, 1000), 0, 0);

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1) return ValueTask.CompletedTask;
        _out.Writer.TryComplete();
        try { _stream.Dispose(); } catch { }
        try { if (_client.IsConnected) _client.Disconnect(); } catch { }
        _client.Dispose();
        return ValueTask.CompletedTask;
    }
}

public sealed class SshSftpSession(SftpClient client, string hostKeySha256) : ISftpSession
{
    public string HostKeySha256 { get; } = hostKeySha256;

    public string Home { get; } = client.WorkingDirectory;

    public async Task<IReadOnlyList<SftpEntry>> ListAsync(string path, CancellationToken ct)
    {
        var list = new List<SftpEntry>();
        await foreach (var f in client.ListDirectoryAsync(path, ct).ConfigureAwait(false))
        {
            if (f.Name is "." or "..") continue;
            list.Add(ToEntry(f));
        }
        return list.OrderByDescending(e => e.IsDirectory).ThenBy(e => e.Name, StringComparer.Ordinal).ToList();
    }

    public async Task<SftpEntry> StatAsync(string path, CancellationToken ct) =>
        ToEntry(await client.GetAsync(path, ct).ConfigureAwait(false));

    public Task DownloadAsync(string path, Stream destination, CancellationToken ct) =>
        client.DownloadFileAsync(path, destination, ct);

    public Task UploadAsync(Stream source, string path, bool overwrite, CancellationToken ct) =>
        client.UploadFileAsync(source, path, overwrite, null, ct);

    public Task CreateDirectoryAsync(string path, CancellationToken ct) => client.CreateDirectoryAsync(path, ct);

    public Task RenameAsync(string from, string to, CancellationToken ct) => client.RenameFileAsync(from, to, ct);

    public async Task DeleteAsync(string path, CancellationToken ct)
    {
        var f = await client.GetAsync(path, ct).ConfigureAwait(false);
        if (f.IsDirectory && !f.IsSymbolicLink) await client.DeleteDirectoryAsync(path, ct).ConfigureAwait(false);
        else await client.DeleteFileAsync(path, ct).ConfigureAwait(false);
    }

    private static SftpEntry ToEntry(ISftpFile f) => new(
        f.Name, f.FullName, f.IsDirectory, f.IsSymbolicLink, f.Length,
        new DateTimeOffset(DateTime.SpecifyKind(f.LastWriteTimeUtc, DateTimeKind.Utc)), Mode(f));

    private static string Mode(ISftpFile f)
    {
        var type = f.IsDirectory ? 'd' : f.IsSymbolicLink ? 'l' : '-';
        return string.Concat(
            type,
            f.OwnerCanRead ? 'r' : '-', f.OwnerCanWrite ? 'w' : '-', f.OwnerCanExecute ? 'x' : '-',
            f.GroupCanRead ? 'r' : '-', f.GroupCanWrite ? 'w' : '-', f.GroupCanExecute ? 'x' : '-',
            f.OthersCanRead ? 'r' : '-', f.OthersCanWrite ? 'w' : '-', f.OthersCanExecute ? 'x' : '-');
    }

    public ValueTask DisposeAsync()
    {
        try { if (client.IsConnected) client.Disconnect(); } catch { }
        client.Dispose();
        return ValueTask.CompletedTask;
    }
}
