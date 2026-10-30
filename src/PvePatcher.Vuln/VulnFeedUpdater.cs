using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PvePatcher.Core;

namespace PvePatcher.Vuln;

public sealed partial class VulnFeedUpdater : IVulnFeedUpdater
{
    public const string HttpClientName = "pve-patcher-vuln";

    private readonly VulnDatabase _db;
    private readonly VulnOptions _options;
    private readonly IHttpClientFactory _http;
    private readonly ISecretStore? _secrets;
    private readonly ILogger _log;

    public VulnFeedUpdater(
        VulnDatabase db,
        IOptions<VulnOptions> options,
        IHttpClientFactory http,
        ISecretStore? secrets = null,
        ILogger<VulnFeedUpdater>? log = null)
    {
        _db = db;
        _options = options.Value;
        _http = http;
        _secrets = secrets;
        _log = (ILogger?)log ?? NullLogger.Instance;
    }

    // ---------------------------------------------------------------- UpdateAsync

    public async Task UpdateAsync(IReadOnlyCollection<OsInfo> releasesInUse, CancellationToken ct)
    {
        Directory.CreateDirectory(_options.CacheDir);
        var errors = new List<Exception>();

        var ecosystems = releasesInUse
            .Select(OsvEcosystems.FromOs)
            .Where(e => e is not null)
            .Select(e => e!)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        foreach (var group in ecosystems.GroupBy(OsvEcosystems.Parent))
        {
            try
            {
                await UpdateOsvGroupAsync(group.Key, group.ToHashSet(StringComparer.Ordinal), ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log.LogError(ex, "Falha ao atualizar OSV {Parent}", group.Key);
                foreach (var eco in group) SaveError($"osv:{eco}", ex.Message);
                errors.Add(ex);
            }
        }

        await TryFeed("kev", () => UpdateKevAsync(ct), errors);
        await TryFeed("epss", () => UpdateEpssAsync(ct), errors);

        if (errors.Count > 0) throw new AggregateException("Falha ao atualizar um ou mais feeds de vulnerabilidades", errors);
    }

    private async Task TryFeed(string name, Func<Task> action, List<Exception> errors)
    {
        try
        {
            await action();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "Falha ao atualizar feed {Feed}", name);
            SaveError(name, ex.Message);
            errors.Add(ex);
        }
    }

    // ---------------------------------------------------------------- OSV

    private async Task UpdateOsvGroupAsync(string parent, HashSet<string> wanted, CancellationToken ct)
    {
        var url = $"{_options.OsvBaseUrl.TrimEnd('/')}/{Uri.EscapeDataString(parent)}/all.zip";
        var file = Path.Combine(_options.CacheDir, $"osv-{Regex.Replace(parent, @"[^A-Za-z0-9]+", "_")}.zip");

        var missing = wanted.Any(e => GetState($"osv:{e}") is not { UpdatedAt: not null, LastError: null });
        var download = await DownloadAsync(url, file, ct);
        if (!download.Changed && !missing)
        {
            _log.LogInformation("OSV {Parent} sem alterações", parent);
            foreach (var eco in wanted) TouchState($"osv:{eco}");
            return;
        }

        _log.LogInformation("Processando OSV {Parent} ({Ecosystems})", parent, string.Join(", ", wanted));
        var sw = Stopwatch.StartNew();
        var counts = await Task.Run(() => IngestZip(file, wanted, ct), ct);
        SaveHttpCache(url, download);
        foreach (var eco in wanted)
            SaveState($"osv:{eco}", counts.GetValueOrDefault(eco));
        _log.LogInformation("OSV {Parent} processado em {Elapsed}", parent, sw.Elapsed);
    }

    /// <summary>Lê o zip em streaming, uma entrada por vez, e troca as linhas dos ecossistemas pedidos numa transação.</summary>
    internal Dictionary<string, int> IngestZip(string zipPath, ISet<string> wanted, CancellationToken ct)
    {
        using var conn = _db.Open();
        using var tx = conn.BeginTransaction();

        var names = wanted.ToList();
        using (var del = conn.CreateCommand())
        {
            del.Transaction = tx;
            del.CommandText = $"DELETE FROM osv_range WHERE ecosystem IN ({string.Join(",", names.Select((_, i) => $"@e{i}"))})";
            for (var i = 0; i < names.Count; i++) del.Parameters.AddWithValue($"@e{i}", names[i]);
            del.ExecuteNonQuery();
        }

        using var insRange = Prepare(conn, tx,
            "INSERT INTO osv_range(ecosystem,pkg,vuln_id,introduced,fixed,last_affected,severity) VALUES(@e,@p,@v,@i,@f,@l,@s)",
            "@e", "@p", "@v", "@i", "@f", "@l", "@s");
        using var insVuln = Prepare(conn, tx,
            "INSERT OR REPLACE INTO osv_vuln(vuln_id,is_advisory,summary,cvss_vector,cvss_score) VALUES(@v,@a,@m,@x,@c)",
            "@v", "@a", "@m", "@x", "@c");
        using var delAlias = Prepare(conn, tx, "DELETE FROM osv_alias WHERE vuln_id=@v", "@v");
        using var insAlias = Prepare(conn, tx, "INSERT OR IGNORE INTO osv_alias(vuln_id,cve_id) VALUES(@v,@c)", "@v", "@c");

        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        var buffer = new MemoryStream();
        var total = 0;
        var malformed = 0;

        using var zip = ZipFile.OpenRead(zipPath);
        foreach (var entry in zip.Entries)
        {
            ct.ThrowIfCancellationRequested();
            if (!entry.Name.EndsWith(".json", StringComparison.OrdinalIgnoreCase)) continue;
            if (++total % 25000 == 0) _log.LogInformation("OSV: {Count} registros lidos", total);

            buffer.SetLength(0);
            using (var s = entry.Open()) s.CopyTo(buffer);

            OsvRecord? rec;
            try
            {
                rec = OsvParser.Parse(buffer.GetBuffer().AsMemory(0, (int)buffer.Length), wanted.Contains);
            }
            catch (JsonException)
            {
                malformed++;
                continue;
            }
            if (rec is null) continue;

            insVuln.Parameters["@v"].Value = rec.Id;
            insVuln.Parameters["@a"].Value = rec.IsAdvisory ? 1 : 0;
            insVuln.Parameters["@m"].Value = (object?)rec.Summary ?? DBNull.Value;
            insVuln.Parameters["@x"].Value = (object?)rec.CvssVector ?? DBNull.Value;
            insVuln.Parameters["@c"].Value = rec.CvssScore is { } sc ? sc : DBNull.Value;
            insVuln.ExecuteNonQuery();

            delAlias.Parameters["@v"].Value = rec.Id;
            delAlias.ExecuteNonQuery();
            foreach (var cve in rec.CveIds)
            {
                insAlias.Parameters["@v"].Value = rec.Id;
                insAlias.Parameters["@c"].Value = cve;
                insAlias.ExecuteNonQuery();
            }

            foreach (var r in rec.Ranges)
            {
                insRange.Parameters["@e"].Value = r.Ecosystem;
                insRange.Parameters["@p"].Value = r.Package.ToLowerInvariant();
                insRange.Parameters["@v"].Value = rec.Id;
                insRange.Parameters["@i"].Value = (object?)r.Introduced ?? DBNull.Value;
                insRange.Parameters["@f"].Value = (object?)r.Fixed ?? DBNull.Value;
                insRange.Parameters["@l"].Value = (object?)r.LastAffected ?? DBNull.Value;
                insRange.Parameters["@s"].Value = (object?)r.DistroSeverity ?? DBNull.Value;
                insRange.ExecuteNonQuery();
                counts[r.Ecosystem] = counts.GetValueOrDefault(r.Ecosystem) + 1;
            }
        }

        VulnDatabase.Exec(conn, "DELETE FROM osv_vuln WHERE vuln_id NOT IN (SELECT DISTINCT vuln_id FROM osv_range)", tx);
        VulnDatabase.Exec(conn, "DELETE FROM osv_alias WHERE vuln_id NOT IN (SELECT vuln_id FROM osv_vuln)", tx);
        tx.Commit();

        if (malformed > 0) _log.LogWarning("OSV: {Count} registros malformados ignorados", malformed);
        return counts;
    }

    private static SqliteCommand Prepare(SqliteConnection conn, SqliteTransaction tx, string sql, params string[] parameters)
    {
        var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        foreach (var p in parameters) cmd.Parameters.Add(p, SqliteType.Text);
        return cmd;
    }

    // ---------------------------------------------------------------- KEV

    private async Task UpdateKevAsync(CancellationToken ct)
    {
        var file = Path.Combine(_options.CacheDir, "kev.json");
        var download = await DownloadAsync(_options.KevUrl, file, ct);
        if (!download.Changed && GetState("kev") is { UpdatedAt: not null, LastError: null })
        {
            TouchState("kev");
            return;
        }

        var cves = new List<string>();
        await using (var fs = File.OpenRead(file))
        {
            using var doc = await JsonDocument.ParseAsync(fs, cancellationToken: ct);
            if (doc.RootElement.TryGetProperty("vulnerabilities", out var arr))
                foreach (var v in arr.EnumerateArray())
                    if (v.TryGetProperty("cveID", out var id) && id.GetString() is { } s)
                        cves.Add(s.Trim().ToUpperInvariant());
        }

        using (var conn = _db.Open())
        using (var tx = conn.BeginTransaction())
        {
            VulnDatabase.Exec(conn, "DELETE FROM kev", tx);
            using var ins = Prepare(conn, tx, "INSERT OR IGNORE INTO kev(cve_id) VALUES(@c)", "@c");
            foreach (var c in cves)
            {
                ins.Parameters["@c"].Value = c;
                ins.ExecuteNonQuery();
            }
            tx.Commit();
        }
        SaveHttpCache(_options.KevUrl, download);
        SaveState("kev", cves.Count);
    }

    // ---------------------------------------------------------------- EPSS

    private async Task UpdateEpssAsync(CancellationToken ct)
    {
        var file = Path.Combine(_options.CacheDir, "epss.csv.gz");
        var download = await DownloadAsync(_options.EpssUrl, file, ct);
        if (!download.Changed && GetState("epss") is { UpdatedAt: not null, LastError: null })
        {
            TouchState("epss");
            return;
        }

        var count = await Task.Run(() => IngestEpss(file, ct), ct);
        SaveHttpCache(_options.EpssUrl, download);
        SaveState("epss", count);
    }

    internal int IngestEpss(string file, CancellationToken ct)
    {
        using var raw = File.OpenRead(file);
        var b0 = raw.ReadByte();
        var b1 = raw.ReadByte();
        raw.Position = 0;
        Stream input = b0 == 0x1f && b1 == 0x8b ? new GZipStream(raw, CompressionMode.Decompress) : raw;
        using var reader = new StreamReader(input);

        using var conn = _db.Open();
        using var tx = conn.BeginTransaction();
        VulnDatabase.Exec(conn, "DELETE FROM epss", tx);
        using var ins = Prepare(conn, tx, "INSERT OR REPLACE INTO epss(cve_id,score) VALUES(@c,@s)", "@c", "@s");

        var count = 0;
        while (reader.ReadLine() is { } line)
        {
            if ((count & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
            if (line.Length == 0 || line[0] == '#' || line.StartsWith("cve,", StringComparison.OrdinalIgnoreCase)) continue;
            var parts = line.Split(',');
            if (parts.Length < 2 || !double.TryParse(parts[1], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var score)) continue;
            ins.Parameters["@c"].Value = parts[0].Trim().ToUpperInvariant();
            ins.Parameters["@s"].Value = score;
            ins.ExecuteNonQuery();
            count++;
        }
        tx.Commit();
        return count;
    }

    // ---------------------------------------------------------------- NVD

    public async Task EnrichAsync(IReadOnlyCollection<string> cveIds, Action<string>? log, CancellationToken ct)
    {
        var todo = SelectCvesToFetch(cveIds);
        if (todo.Count == 0) return;

        string? apiKey = null;
        if (_secrets is not null)
        {
            try
            {
                var data = await _secrets.ReadAsync(SecretPaths.Nvd, ct);
                if (data is not null && data.TryGetValue(SecretPaths.ApiKey, out var k) && !string.IsNullOrWhiteSpace(k))
                    apiKey = k.Trim();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log.LogWarning("Cofre indisponível; NVD sem API key ({Message})", ex.Message);
            }
        }

        var perWindow = apiKey is null ? _options.NvdRequestsWithoutKey : _options.NvdRequestsWithKey;
        var limiter = new SlidingWindowRateLimiter(perWindow, _options.NvdWindow);
        var client = _http.CreateClient(HttpClientName);
        var failures = 0;
        string? lastError = null;

        // Tempo máximo neste scan: a fila é serial e, sem API key, centenas de CVEs levariam horas.
        var budget = _options.NvdBudgetPerScan;
        using var budgetCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (budget > TimeSpan.Zero) budgetCts.CancelAfter(budget);
        log?.Invoke($"NVD: {todo.Count} CVE(s) sem nota no cache, {(apiKey is null ? "sem API key" : "com API key")} " +
                    $"({perWindow} consultas a cada {_options.NvdWindow.TotalSeconds:0} s)" +
                    (budget > TimeSpan.Zero ? $"; até {budget.TotalMinutes:0.#} min neste scan." : "."));

        var done = 0;
        var lastReport = Stopwatch.GetTimestamp();
        foreach (var cve in todo)
        {
            ct.ThrowIfCancellationRequested();
            if (budgetCts.IsCancellationRequested) break;
            try
            {
                var result = await FetchNvdAsync(client, limiter, cve, apiKey, budgetCts.Token);
                if (result is null) failures++;
                else SaveNvd(cve, result.Value);
            }
            catch (OperationCanceledException) when (budgetCts.IsCancellationRequested && !ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                // Inclui o timeout do HttpClient (OperationCanceledException sem o ct cancelado).
                failures++;
                lastError = ex.Message;
                _log.LogWarning("NVD {Cve}: {Message}", cve, ex.Message);
            }
            done++;
            if (Stopwatch.GetElapsedTime(lastReport) >= TimeSpan.FromSeconds(20))
            {
                log?.Invoke($"NVD: {done}/{todo.Count} consultados...");
                lastReport = Stopwatch.GetTimestamp();
            }
        }
        if (done < todo.Count)
            log?.Invoke($"NVD: limite de {budget.TotalMinutes:0.#} min atingido; {todo.Count - done} CVE(s) ficam para os próximos scans " +
                        "(por ora valem a severidade da distro, KEV e EPSS)." +
                        (apiKey is null ? " Cadastre a API key do NVD em Configurações para consultas 10x mais rápidas." : ""));

        using var conn = _db.Open();
        VulnDatabase.Exec(conn,
            "INSERT INTO feed_state(name,updated_at,records,last_error) VALUES('nvd',NULL,0,@e) " +
            "ON CONFLICT(name) DO UPDATE SET last_error=@e",
            null, ("@e", failures > 0 ? (lastError ?? $"{failures} consulta(s) falharam") : null));
    }

    private List<string> SelectCvesToFetch(IReadOnlyCollection<string> cveIds)
    {
        var wanted = cveIds
            .Select(c => c.Trim().ToUpperInvariant())
            .Where(c => CveIdRegex().IsMatch(c))
            .Distinct()
            .ToList();
        if (wanted.Count == 0) return wanted;

        var cutoff = DateTimeOffset.UtcNow - _options.NvdRetryUnscored;
        var skip = new HashSet<string>(StringComparer.Ordinal);
        using var conn = _db.Open();
        foreach (var chunk in wanted.Chunk(500))
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = $"SELECT cve_id, cvss, fetched_at FROM nvd_cache WHERE cve_id IN ({string.Join(",", chunk.Select((_, i) => $"@c{i}"))})";
            for (var i = 0; i < chunk.Length; i++) cmd.Parameters.AddWithValue($"@c{i}", chunk[i]);
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                var scored = !r.IsDBNull(1);
                var fetched = DateTimeOffset.TryParse(r.GetString(2), out var f) ? f : DateTimeOffset.MinValue;
                if (scored || fetched > cutoff) skip.Add(r.GetString(0));
            }
        }
        return wanted.Where(c => !skip.Contains(c)).ToList();
    }

    private async Task<NvdCvss?> FetchNvdAsync(HttpClient client, SlidingWindowRateLimiter limiter, string cve, string? apiKey, CancellationToken ct)
    {
        for (var attempt = 0; attempt < 2; attempt++)
        {
            await limiter.WaitAsync(ct);
            using var req = new HttpRequestMessage(HttpMethod.Get, $"{_options.NvdUrl}?cveId={Uri.EscapeDataString(cve)}");
            if (apiKey is not null) req.Headers.TryAddWithoutValidation("apiKey", apiKey);
            using var resp = await client.SendAsync(req, ct);

            if (resp.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable)
            {
                await Task.Delay(_options.NvdWindow, ct);
                continue;
            }
            if (resp.StatusCode == HttpStatusCode.NotFound) return new NvdCvss(null, null, null);
            resp.EnsureSuccessStatusCode();

            await using var stream = await resp.Content.ReadAsStreamAsync(ct);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
            return NvdParser.ParseCvss(doc.RootElement);
        }
        return null;
    }

    private void SaveNvd(string cve, NvdCvss value)
    {
        using var conn = _db.Open();
        VulnDatabase.Exec(conn,
            "INSERT OR REPLACE INTO nvd_cache(cve_id,cvss,vector,version,fetched_at) VALUES(@c,@s,@v,@n,@t)", null,
            ("@c", cve), ("@s", value.Score), ("@v", value.Vector), ("@n", value.Version), ("@t", DateTimeOffset.UtcNow.ToString("O")));
    }

    [GeneratedRegex(@"^CVE-\d{4}-\d{4,}$")]
    private static partial Regex CveIdRegex();

    // ---------------------------------------------------------------- Status

    public Task<IReadOnlyList<FeedState>> GetStatusAsync(CancellationToken ct)
    {
        var list = new List<FeedState>();
        using var conn = _db.Open();
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "SELECT name, updated_at, records, last_error FROM feed_state WHERE name <> 'nvd' ORDER BY name";
            using var r = cmd.ExecuteReader();
            while (r.Read())
                list.Add(new FeedState(r.GetString(0), ParseDate(r, 1), r.GetInt32(2), r.IsDBNull(3) ? null : r.GetString(3)));
        }

        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText =
                "SELECT COUNT(cvss), MAX(fetched_at), (SELECT last_error FROM feed_state WHERE name='nvd') FROM nvd_cache";
            using var r = cmd.ExecuteReader();
            if (r.Read())
                list.Add(new FeedState("nvd", ParseDate(r, 1), r.GetInt32(0), r.IsDBNull(2) ? null : r.GetString(2)));
        }
        return Task.FromResult<IReadOnlyList<FeedState>>(list);
    }

    private static DateTimeOffset? ParseDate(SqliteDataReader r, int i) =>
        !r.IsDBNull(i) && DateTimeOffset.TryParse(r.GetString(i), out var d) ? d : null;

    private FeedState? GetState(string name)
    {
        using var conn = _db.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT updated_at, records, last_error FROM feed_state WHERE name=@n";
        cmd.Parameters.AddWithValue("@n", name);
        using var r = cmd.ExecuteReader();
        return r.Read()
            ? new FeedState(name, ParseDate(r, 0), r.GetInt32(1), r.IsDBNull(2) ? null : r.GetString(2))
            : null;
    }

    private void SaveState(string name, int records)
    {
        using var conn = _db.Open();
        VulnDatabase.Exec(conn,
            "INSERT INTO feed_state(name,updated_at,records,last_error) VALUES(@n,@t,@r,NULL) " +
            "ON CONFLICT(name) DO UPDATE SET updated_at=@t, records=@r, last_error=NULL", null,
            ("@n", name), ("@t", DateTimeOffset.UtcNow.ToString("O")), ("@r", records));
    }

    // Sem alterações no servidor: só renova o carimbo
    private void TouchState(string name)
    {
        using var conn = _db.Open();
        VulnDatabase.Exec(conn,
            "UPDATE feed_state SET updated_at=@t, last_error=NULL WHERE name=@n", null,
            ("@n", name), ("@t", DateTimeOffset.UtcNow.ToString("O")));
    }

    private void SaveError(string name, string error)
    {
        try
        {
            using var conn = _db.Open();
            VulnDatabase.Exec(conn,
                "INSERT INTO feed_state(name,updated_at,records,last_error) VALUES(@n,NULL,0,@e) " +
                "ON CONFLICT(name) DO UPDATE SET last_error=@e", null,
                ("@n", name), ("@e", error));
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Não foi possível gravar o erro do feed {Feed}", name);
        }
    }

    // ---------------------------------------------------------------- HTTP condicional

    private sealed record Download(bool Changed, string? ETag, string? LastModified);

    private async Task<Download> DownloadAsync(string url, string file, CancellationToken ct)
    {
        var client = _http.CreateClient(HttpClientName);
        using var req = new HttpRequestMessage(HttpMethod.Get, url);

        if (File.Exists(file))
        {
            using var conn = _db.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT etag, last_modified FROM http_cache WHERE url=@u";
            cmd.Parameters.AddWithValue("@u", url);
            using var r = cmd.ExecuteReader();
            if (r.Read())
            {
                if (!r.IsDBNull(0)) req.Headers.TryAddWithoutValidation("If-None-Match", r.GetString(0));
                if (!r.IsDBNull(1)) req.Headers.TryAddWithoutValidation("If-Modified-Since", r.GetString(1));
            }
        }

        using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        if (resp.StatusCode == HttpStatusCode.NotModified) return new Download(false, null, null);
        resp.EnsureSuccessStatusCode();

        var partial = file + ".partial";
        await using (var fs = File.Create(partial))
        await using (var body = await resp.Content.ReadAsStreamAsync(ct))
            await body.CopyToAsync(fs, 81920, ct);
        File.Move(partial, file, overwrite: true);

        var etag = resp.Headers.ETag?.ToString();
        var lm = resp.Content.Headers.LastModified?.ToString("R");
        return new Download(true, etag, lm);
    }

    // O validador só é gravado depois que o conteúdo foi processado com sucesso
    private void SaveHttpCache(string url, Download d)
    {
        if (!d.Changed) return;
        using var conn = _db.Open();
        VulnDatabase.Exec(conn,
            "INSERT OR REPLACE INTO http_cache(url,etag,last_modified) VALUES(@u,@e,@l)", null,
            ("@u", url), ("@e", d.ETag), ("@l", d.LastModified));
    }
}

public readonly record struct NvdCvss(double? Score, string? Vector, string? Version);

public static class NvdParser
{
    private static readonly string[] MetricKeys = ["cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"];

    /// <summary>Melhor nota da resposta da API 2.0 (v3.1 &gt; v4.0 &gt; v3.0 &gt; v2; Primary antes de Secondary). Pontuação nula = ainda sem nota.</summary>
    public static NvdCvss ParseCvss(JsonElement root)
    {
        if (!root.TryGetProperty("vulnerabilities", out var vulns) || vulns.ValueKind != JsonValueKind.Array || vulns.GetArrayLength() == 0)
            return new NvdCvss(null, null, null);
        var cve = vulns[0].GetProperty("cve");
        if (!cve.TryGetProperty("metrics", out var metrics)) return new NvdCvss(null, null, null);

        foreach (var key in MetricKeys)
        {
            if (!metrics.TryGetProperty(key, out var arr) || arr.ValueKind != JsonValueKind.Array || arr.GetArrayLength() == 0) continue;

            JsonElement chosen = arr[0];
            foreach (var m in arr.EnumerateArray())
                if (m.TryGetProperty("type", out var t) && t.GetString() == "Primary") { chosen = m; break; }

            if (!chosen.TryGetProperty("cvssData", out var data)) continue;
            if (!data.TryGetProperty("baseScore", out var score) || score.ValueKind != JsonValueKind.Number) continue;
            var vector = data.TryGetProperty("vectorString", out var v) ? v.GetString() : null;
            var version = data.TryGetProperty("version", out var ver) ? ver.GetString() : null;
            return new NvdCvss(score.GetDouble(), vector, version);
        }
        return new NvdCvss(null, null, null);
    }
}

/// <summary>No máximo N requisições por janela deslizante.</summary>
internal sealed class SlidingWindowRateLimiter(int max, TimeSpan window)
{
    private readonly Queue<long> _stamps = new();
    private readonly object _lock = new();

    public async Task WaitAsync(CancellationToken ct)
    {
        while (true)
        {
            TimeSpan wait;
            lock (_lock)
            {
                var now = Stopwatch.GetTimestamp();
                while (_stamps.Count > 0 && Stopwatch.GetElapsedTime(_stamps.Peek(), now) >= window) _stamps.Dequeue();
                if (_stamps.Count < max)
                {
                    _stamps.Enqueue(now);
                    return;
                }
                wait = window - Stopwatch.GetElapsedTime(_stamps.Peek(), now);
            }
            if (wait < TimeSpan.FromMilliseconds(1)) wait = TimeSpan.FromMilliseconds(1);
            await Task.Delay(wait, ct);
        }
    }
}
