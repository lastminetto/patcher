using System.Collections.Concurrent;
using System.Text;
using System.Threading.Channels;
using PvePatcher.Core;

namespace PvePatcher.Web.Dev;

/// <summary>Só para desenvolvimento: shell de brinquedo (eco, prompt, alguns comandos) e SFTP em memória.</summary>
public sealed class FakeConsoleConnector : IConsoleConnector
{
    private readonly FakeFileSystem _fs = new();

    public async Task<IShellSession> OpenShellAsync(SshTarget target, int cols, int rows, CancellationToken ct)
    {
        await Task.Delay(300, ct);
        return new FakeShell(target.User, target.Host, Check(target), cols, rows);
    }

    public async Task<ISftpSession> OpenSftpAsync(SshTarget target, CancellationToken ct)
    {
        await Task.Delay(150, ct);
        return new FakeSftp(_fs, Check(target), target.User == "root" ? "/root" : $"/home/{target.User}");
    }

    private static string Check(SshTarget target)
    {
        var key = FakeWorld.HostKeyOf(target.Host);
        if (target.KnownHostKeySha256 is not null && target.KnownHostKeySha256 != key)
            throw new HostKeyMismatchException(target.KnownHostKeySha256, key);
        return key;
    }
}

public sealed class FakeShell : IShellSession
{
    private readonly Channel<byte[]> _out = Channel.CreateUnbounded<byte[]>();
    private readonly StringBuilder _line = new();
    private readonly string _user, _host;
    private int _cols, _rows;

    public FakeShell(string user, string host, string hostKey, int cols, int rows)
    {
        (_user, _host, HostKeySha256, _cols, _rows) = (user, host, hostKey, cols, rows);
        Emit($"Shell FAKE (Dev:UseFakes) em {host}. Comandos: ls, uname, whoami, size, colors, exit\r\n");
        Prompt();
    }

    public string HostKeySha256 { get; }

    private void Emit(string s) => _out.Writer.TryWrite(Encoding.UTF8.GetBytes(s));
    private void Prompt() => Emit($"\x1b[32m{_user}@fake-{_host}\x1b[0m:\x1b[34m~\x1b[0m$ ");

    public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct)
    {
        if (!await _out.Reader.WaitToReadAsync(ct)) return 0;
        var chunk = await _out.Reader.ReadAsync(ct);
        chunk.CopyTo(buffer); // pedaços pequenos (eco/linhas), sempre menores que o buffer
        return chunk.Length;
    }

    public ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken ct)
    {
        foreach (var ch in Encoding.UTF8.GetString(data.Span))
        {
            switch (ch)
            {
                case '\r':
                    Emit("\r\n");
                    Run(_line.ToString().Trim());
                    _line.Clear();
                    break;
                case '\x7f' or '\b':
                    if (_line.Length > 0) { _line.Length--; Emit("\b \b"); }
                    break;
                case '\x03':
                    _line.Clear(); Emit("^C\r\n"); Prompt();
                    break;
                default:
                    if (!char.IsControl(ch)) { _line.Append(ch); Emit(ch.ToString()); }
                    break;
            }
        }
        return ValueTask.CompletedTask;
    }

    private void Run(string cmd)
    {
        switch (cmd)
        {
            case "": break;
            case "exit": Emit("logout\r\n"); _out.Writer.TryComplete(); return;
            case "ls": Emit("\x1b[34mdocs\x1b[0m  notas.txt  script.sh\r\n"); break;
            case "uname" or "uname -a": Emit("Linux fake 6.12.0-fake #1 SMP x86_64 GNU/Linux\r\n"); break;
            case "whoami": Emit(_user + "\r\n"); break;
            case "size": Emit($"{_cols}x{_rows}\r\n"); break;
            case "colors":
                for (var i = 0; i < 8; i++) Emit($"\x1b[4{i}m  \x1b[0m");
                Emit("\r\n");
                break;
            default: Emit($"fake-sh: {cmd}: comando não encontrado\r\n"); break;
        }
        Prompt();
    }

    public void Resize(int cols, int rows) => (_cols, _rows) = (cols, rows);

    public ValueTask DisposeAsync()
    {
        _out.Writer.TryComplete();
        return ValueTask.CompletedTask;
    }
}

/// <summary>Árvore de arquivos em memória compartilhada pelas sessões SFTP falsas.</summary>
public sealed class FakeFileSystem
{
    public ConcurrentDictionary<string, (bool Dir, byte[] Data, DateTimeOffset Mtime)> Nodes { get; } = new(StringComparer.Ordinal);

    public FakeFileSystem()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var d in new[] { "/", "/root", "/root/docs", "/home", "/etc" }) Nodes[d] = (true, [], now);
        Nodes["/root/notas.txt"] = (false, Encoding.UTF8.GetBytes("arquivo de exemplo\n"), now);
        Nodes["/root/script.sh"] = (false, Encoding.UTF8.GetBytes("#!/bin/sh\necho oi\n"), now);
        Nodes["/etc/hostname"] = (false, Encoding.UTF8.GetBytes("fake\n"), now);
    }
}

public sealed class FakeSftp(FakeFileSystem fs, string hostKey, string home) : ISftpSession
{
    public string HostKeySha256 { get; } = hostKey;
    public string Home { get; } = fs.Nodes.ContainsKey(home) ? home : "/root";

    private static string Parent(string p) { var i = p.TrimEnd('/').LastIndexOf('/'); return i <= 0 ? "/" : p[..i]; }

    private SftpEntry Entry(string path)
    {
        if (!fs.Nodes.TryGetValue(path, out var n)) throw new FileNotFoundException("Caminho não encontrado.");
        var name = path == "/" ? "/" : path[(path.LastIndexOf('/') + 1)..];
        return new SftpEntry(name, path, n.Dir, false, n.Data.LongLength, n.Mtime, n.Dir ? "drwxr-xr-x" : "-rw-r--r--");
    }

    public Task<IReadOnlyList<SftpEntry>> ListAsync(string path, CancellationToken ct)
    {
        if (!Entry(path).IsDirectory) throw new IOException("Não é um diretório.");
        IReadOnlyList<SftpEntry> list = fs.Nodes.Keys.Where(k => k != "/" && k != path && Parent(k) == path)
            .Select(Entry).OrderByDescending(e => e.IsDirectory).ThenBy(e => e.Name, StringComparer.Ordinal).ToList();
        return Task.FromResult(list);
    }

    public Task<SftpEntry> StatAsync(string path, CancellationToken ct) => Task.FromResult(Entry(path));

    public async Task DownloadAsync(string path, Stream destination, CancellationToken ct) =>
        await destination.WriteAsync(fs.Nodes[path].Data, ct);

    public async Task UploadAsync(Stream source, string path, bool overwrite, CancellationToken ct)
    {
        if (!overwrite && fs.Nodes.ContainsKey(path)) throw new IOException("Arquivo já existe.");
        if (!fs.Nodes.TryGetValue(Parent(path), out var p) || !p.Dir) throw new IOException("Diretório não existe.");
        using var ms = new MemoryStream();
        await source.CopyToAsync(ms, ct);
        fs.Nodes[path] = (false, ms.ToArray(), DateTimeOffset.UtcNow);
    }

    public Task CreateDirectoryAsync(string path, CancellationToken ct)
    {
        if (!fs.Nodes.TryAdd(path, (true, [], DateTimeOffset.UtcNow))) throw new IOException("Já existe.");
        return Task.CompletedTask;
    }

    public Task RenameAsync(string from, string to, CancellationToken ct)
    {
        if (fs.Nodes.ContainsKey(to)) throw new IOException("Destino já existe.");
        foreach (var k in fs.Nodes.Keys.Where(k => k == from || k.StartsWith(from + "/", StringComparison.Ordinal)).ToList())
            if (fs.Nodes.TryRemove(k, out var v)) fs.Nodes[to + k[from.Length..]] = v;
        return Task.CompletedTask;
    }

    public Task DeleteAsync(string path, CancellationToken ct)
    {
        if (fs.Nodes.Keys.Any(k => k.StartsWith(path + "/", StringComparison.Ordinal))) throw new IOException("Diretório não está vazio.");
        fs.Nodes.TryRemove(path, out _);
        return Task.CompletedTask;
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
