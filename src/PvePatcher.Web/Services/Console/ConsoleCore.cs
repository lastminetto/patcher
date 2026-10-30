using System.Text.Json;

namespace PvePatcher.Web.Services;

/// <summary>Limites do terminal (seção "Console" do appsettings).</summary>
public sealed class ConsoleOptions
{
    public int MaxSessionsPerUser { get; set; } = 10;
    public int MaxSessions { get; set; } = 50;
    public int MaxUploadMegabytes { get; set; } = 2048;
}

/// <summary>Contagem de shells abertos, com limite por usuário e total.</summary>
public sealed class ConsoleSessionRegistry(Microsoft.Extensions.Options.IOptions<ConsoleOptions> options)
{
    private readonly Lock _gate = new();
    private readonly Dictionary<string, int> _byUser = new(StringComparer.Ordinal);
    private int _total;

    public int Total { get { lock (_gate) return _total; } }

    /// <summary>Reserva uma vaga; devolve null e o motivo se algum limite estourou. Liberar com Dispose.</summary>
    public IDisposable? TryAcquire(string user, out string? reason)
    {
        var o = options.Value;
        lock (_gate)
        {
            var mine = _byUser.GetValueOrDefault(user);
            if (_total >= o.MaxSessions) { reason = $"Limite de {o.MaxSessions} sessões de terminal no servidor atingido."; return null; }
            if (mine >= o.MaxSessionsPerUser) { reason = $"Limite de {o.MaxSessionsPerUser} sessões de terminal por usuário atingido; feche alguma aba."; return null; }
            _byUser[user] = mine + 1;
            _total++;
        }
        reason = null;
        return new Lease(this, user);
    }

    private void Release(string user)
    {
        lock (_gate)
        {
            _total--;
            if (_byUser.TryGetValue(user, out var n) && n > 1) _byUser[user] = n - 1;
            else _byUser.Remove(user);
        }
    }

    private sealed class Lease(ConsoleSessionRegistry owner, string user) : IDisposable
    {
        private int _done;
        public void Dispose() { if (Interlocked.Exchange(ref _done, 1) == 0) owner.Release(user); }
    }
}

/// <summary>Protocolo do WebSocket do terminal: bytes crus em frames binários, controle em JSON nos frames de texto.</summary>
public static class TerminalProtocol
{
    public const int MaxDimension = 1000;

    /// <summary>{"t":"resize","c":120,"r":40} → (120, 40). Rejeita tamanhos fora de 1..1000.</summary>
    public static bool TryParseResize(string json, out int cols, out int rows)
    {
        cols = rows = 0;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("t", out var t) || t.GetString() != "resize"
                || !root.TryGetProperty("c", out var c) || c.ValueKind != JsonValueKind.Number || !c.TryGetInt32(out cols)
                || !root.TryGetProperty("r", out var r) || r.ValueKind != JsonValueKind.Number || !r.TryGetInt32(out rows))
                return false;
            return cols is >= 1 and <= MaxDimension && rows is >= 1 and <= MaxDimension;
        }
        catch (JsonException) { return false; }
    }

    public static string Error(string message) => JsonSerializer.Serialize(new { t = "error", m = message });

    public const string Closed = """{"t":"closed"}""";

    /// <summary>"cluster/vmid" → VmKey.</summary>
    public static bool TryParseVm(string? value, out VmKey key)
    {
        key = default;
        if (string.IsNullOrWhiteSpace(value)) return false;
        var i = value.LastIndexOf('/');
        if (i <= 0 || !int.TryParse(value.AsSpan(i + 1), out var id) || id <= 0) return false;
        key = new VmKey(value[..i], id);
        return true;
    }

    /// <summary>
    /// Origin do navegador igual ao host da requisição (scheme + host[:porta], já ajustados pelos forwarded headers).
    /// Barra WebSocket/POST disparados por outro site com o cookie do usuário.
    /// </summary>
    public static bool IsSameOrigin(string? origin, string scheme, string host)
    {
        if (string.IsNullOrEmpty(origin) || !Uri.TryCreate(origin, UriKind.Absolute, out var o)) return false;
        if (!Uri.TryCreate($"{scheme}://{host}", UriKind.Absolute, out var h)) return false;
        return string.Equals(o.Scheme, h.Scheme, StringComparison.OrdinalIgnoreCase)
            && string.Equals(o.Host, h.Host, StringComparison.OrdinalIgnoreCase)
            && o.Port == h.Port;
    }
}

/// <summary>Caminhos remotos do SFTP (sempre POSIX, absolutos).</summary>
public static class SftpPaths
{
    public static string Combine(string dir, string name)
    {
        if (!IsValidName(name)) throw new ArgumentException($"Nome inválido: '{name}'.");
        return dir.EndsWith('/') ? dir + name : dir + "/" + name;
    }

    public static string Parent(string path)
    {
        var p = path.TrimEnd('/');
        if (p.Length == 0) return "/";
        var i = p.LastIndexOf('/');
        return i <= 0 ? "/" : p[..i];
    }

    /// <summary>Um único componente: sem barras, sem NUL, diferente de "." e "..".</summary>
    public static bool IsValidName(string? name) =>
        !string.IsNullOrWhiteSpace(name) && name is not "." and not ".." && name.IndexOfAny(['/', '\0']) < 0 && name.Length <= 255;

    /// <summary>Normaliza para absoluto, resolvendo "." e ".." (só cosmético: quem decide o acesso é o servidor SSH).</summary>
    public static string Normalize(string? path, string home)
    {
        var raw = string.IsNullOrWhiteSpace(path) ? home : path.Trim();
        if (!raw.StartsWith('/')) raw = home.TrimEnd('/') + "/" + raw;
        var parts = new List<string>();
        foreach (var seg in raw.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (seg == ".") continue;
            if (seg == "..") { if (parts.Count > 0) parts.RemoveAt(parts.Count - 1); continue; }
            parts.Add(seg);
        }
        return "/" + string.Join('/', parts);
    }
}
