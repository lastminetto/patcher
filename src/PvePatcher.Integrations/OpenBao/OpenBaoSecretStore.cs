using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using PvePatcher.Core;

namespace PvePatcher.Integrations.OpenBao;

/// <summary>ISecretStore sobre OpenBao (KV v2) com login AppRole. Nunca registra valores de segredo.</summary>
public sealed class OpenBaoSecretStore : ISecretStore, IDisposable
{
    private readonly HttpClient _http;
    private readonly OpenBaoOptions _options;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _loginLock = new(1, 1);
    private readonly ConcurrentDictionary<string, (DateTimeOffset Expires, IReadOnlyDictionary<string, string> Data)> _cache = new();

    private string? _token;
    private DateTimeOffset _renewAt;
    private bool _renewable;

    public OpenBaoSecretStore(HttpClient http, OpenBaoOptions options, TimeProvider? time = null)
    {
        _http = http;
        _options = options;
        _time = time ?? TimeProvider.System;
    }

    public void Dispose() => _loginLock.Dispose();

    public async Task<VaultStatus> GetStatusAsync(CancellationToken ct)
    {
        try
        {
            using var resp = await SendRawAsync(HttpMethod.Get, "sys/seal-status", null, null, ct);
            if (!resp.IsSuccessStatusCode)
                return new VaultStatus(VaultState.Unreachable, $"HTTP {(int)resp.StatusCode} em sys/seal-status");
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
            var root = doc.RootElement;
            if (root.TryGetProperty("initialized", out var init) && init.ValueKind == JsonValueKind.False)
                return new VaultStatus(VaultState.Sealed, "cofre não inicializado");
            if (root.TryGetProperty("sealed", out var sealedEl) && sealedEl.ValueKind == JsonValueKind.True)
                return new VaultStatus(VaultState.Sealed, "cofre selado");
        }
        catch (Exception e) when (IsNetworkError(e, ct))
        {
            return new VaultStatus(VaultState.Unreachable, e.Message);
        }

        try
        {
            await EnsureTokenAsync(false, ct);
            return new VaultStatus(VaultState.Ready, null);
        }
        catch (VaultUnavailableException e)
        {
            return e.Status;
        }
    }

    public async Task<IReadOnlyDictionary<string, string>?> ReadAsync(string path, CancellationToken ct)
    {
        if (_cache.TryGetValue(path, out var hit) && hit.Expires > _time.GetUtcNow())
            return hit.Data;

        using var resp = await SendAuthedAsync(HttpMethod.Get, DataPath(path), null, ct);
        if (resp.StatusCode == HttpStatusCode.NotFound)
            return null;
        await EnsureSuccessAsync(resp, ct);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        if (!doc.RootElement.TryGetProperty("data", out var outer) || outer.ValueKind != JsonValueKind.Object ||
            !outer.TryGetProperty("data", out var inner) || inner.ValueKind != JsonValueKind.Object)
            return null; // versão apagada: data.data = null

        var result = new Dictionary<string, string>();
        foreach (var p in inner.EnumerateObject())
            result[p.Name] = p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString()! : p.Value.GetRawText();

        if (_options.CacheTtl > TimeSpan.Zero)
            _cache[path] = (_time.GetUtcNow() + _options.CacheTtl, result);
        return result;
    }

    public async Task WriteAsync(string path, IReadOnlyDictionary<string, string> data, CancellationToken ct)
    {
        _cache.TryRemove(path, out _);
        using var resp = await SendAuthedAsync(HttpMethod.Post, DataPath(path), new { data }, ct);
        await EnsureSuccessAsync(resp, ct);
    }

    public async Task DeleteAsync(string path, CancellationToken ct)
    {
        _cache.TryRemove(path, out _);
        using var resp = await SendAuthedAsync(HttpMethod.Delete, $"{Mount}/metadata/{EscapePath(path)}", null, ct);
        if (resp.StatusCode != HttpStatusCode.NotFound)
            await EnsureSuccessAsync(resp, ct);
    }

    private string Mount => _options.KvMount.Trim('/');
    private string DataPath(string path) => $"{Mount}/data/{EscapePath(path)}";
    private static string EscapePath(string path) =>
        string.Join('/', path.Trim('/').Split('/').Select(Uri.EscapeDataString));

    private static bool IsNetworkError(Exception e, CancellationToken ct) =>
        e is HttpRequestException || (e is TaskCanceledException or TimeoutException && !ct.IsCancellationRequested);

    private async Task<HttpResponseMessage> SendRawAsync(HttpMethod method, string path, object? body, string? token, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(method, $"{_options.Address.TrimEnd('/')}/v1/{path}");
        if (token is not null)
            req.Headers.TryAddWithoutValidation("X-Vault-Token", token);
        if (body is not null)
            req.Content = JsonContent.Create(body);
        return await _http.SendAsync(req, ct);
    }

    /// <summary>Envia com o client token; em 403 descarta o token, refaz o login e tenta uma vez mais.</summary>
    private async Task<HttpResponseMessage> SendAuthedAsync(HttpMethod method, string path, object? body, CancellationToken ct)
    {
        for (var attempt = 0; ; attempt++)
        {
            var token = await EnsureTokenAsync(attempt > 0, ct);
            HttpResponseMessage resp;
            try
            {
                resp = await SendRawAsync(method, path, body, token, ct);
            }
            catch (Exception e) when (IsNetworkError(e, ct))
            {
                throw new VaultUnavailableException(new VaultStatus(VaultState.Unreachable, e.Message));
            }

            if (resp.StatusCode == HttpStatusCode.ServiceUnavailable)
            {
                resp.Dispose();
                throw new VaultUnavailableException(new VaultStatus(VaultState.Sealed, "cofre selado"));
            }
            if (resp.StatusCode == HttpStatusCode.Forbidden && attempt == 0)
            {
                resp.Dispose();
                continue;
            }
            return resp;
        }
    }

    private async Task<string> EnsureTokenAsync(bool forceLogin, CancellationToken ct)
    {
        await _loginLock.WaitAsync(ct);
        try
        {
            if (forceLogin)
                _token = null;
            else if (_token is not null && _time.GetUtcNow() < _renewAt)
                return _token;

            if (_token is not null && _renewable && await TryRenewAsync(ct))
                return _token!;

            _token = null;
            await LoginAsync(ct);
            return _token!;
        }
        finally
        {
            _loginLock.Release();
        }
    }

    private async Task<bool> TryRenewAsync(CancellationToken ct)
    {
        try
        {
            using var resp = await SendRawAsync(HttpMethod.Post, "auth/token/renew-self", new { }, _token, ct);
            return resp.IsSuccessStatusCode && ReadAuth(await resp.Content.ReadAsStringAsync(ct), keepToken: true);
        }
        catch (Exception e) when (IsNetworkError(e, ct))
        {
            return false; // o login seguinte reporta Unreachable
        }
    }

    private async Task LoginAsync(CancellationToken ct)
    {
        string roleId, secretId;
        try
        {
            roleId = (await File.ReadAllTextAsync(_options.RoleIdFile, ct)).Trim();
            secretId = (await File.ReadAllTextAsync(_options.SecretIdFile, ct)).Trim();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new VaultUnavailableException(new VaultStatus(VaultState.AuthFailed, $"credenciais AppRole ilegíveis: {e.Message}"));
        }

        HttpResponseMessage resp;
        try
        {
            resp = await SendRawAsync(HttpMethod.Post, "auth/approle/login", new { role_id = roleId, secret_id = secretId }, null, ct);
        }
        catch (Exception e) when (IsNetworkError(e, ct))
        {
            throw new VaultUnavailableException(new VaultStatus(VaultState.Unreachable, e.Message));
        }

        using (resp)
        {
            if (resp.StatusCode == HttpStatusCode.ServiceUnavailable)
                throw new VaultUnavailableException(new VaultStatus(VaultState.Sealed, "cofre selado"));
            if (!resp.IsSuccessStatusCode)
                throw new VaultUnavailableException(new VaultStatus(VaultState.AuthFailed, $"login AppRole recusado (HTTP {(int)resp.StatusCode})"));
            if (!ReadAuth(await resp.Content.ReadAsStringAsync(ct), keepToken: false))
                throw new VaultUnavailableException(new VaultStatus(VaultState.AuthFailed, "resposta de login sem client_token"));
        }
    }

    /// <summary>Lê o objeto "auth" do login/renew e agenda a renovação para 2/3 do TTL.</summary>
    private bool ReadAuth(string json, bool keepToken)
    {
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("auth", out var auth) || auth.ValueKind != JsonValueKind.Object)
            return false;

        if (!keepToken)
        {
            if (!auth.TryGetProperty("client_token", out var tok) || string.IsNullOrEmpty(tok.GetString()))
                return false;
            _token = tok.GetString();
        }

        var ttl = auth.TryGetProperty("lease_duration", out var ld) && ld.TryGetInt32(out var s) ? s : 0;
        _renewable = auth.TryGetProperty("renewable", out var r) && r.ValueKind == JsonValueKind.True;
        _renewAt = _time.GetUtcNow() + TimeSpan.FromSeconds(ttl * 2.0 / 3.0);
        return true;
    }

    private static async Task EnsureSuccessAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        if (resp.IsSuccessStatusCode)
            return;
        if (resp.StatusCode == HttpStatusCode.ServiceUnavailable)
            throw new VaultUnavailableException(new VaultStatus(VaultState.Sealed, "cofre selado"));

        var detail = "";
        try
        {
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.TryGetProperty("errors", out var errs) && errs.ValueKind == JsonValueKind.Array)
                detail = ": " + string.Join("; ", errs.EnumerateArray().Select(e => e.GetString()));
        }
        catch (JsonException) { }
        throw new InvalidOperationException($"OpenBao respondeu HTTP {(int)resp.StatusCode}{detail}");
    }
}
