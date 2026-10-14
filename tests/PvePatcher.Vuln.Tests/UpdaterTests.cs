using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PvePatcher.Core;

namespace PvePatcher.Vuln.Tests;

public class UpdaterTests : IDisposable
{
    private readonly TempVuln _t = new();
    private static readonly OsInfo Deb12 = new(Distro.Debian, "12", "bookworm", "Debian 12");

    public void Dispose() => _t.Dispose();

    private const string KevJson = """{"catalogVersion":"x","vulnerabilities":[{"cveID":"CVE-2023-4863"},{"cveID":"CVE-2024-1"}]}""";
    private const string EpssCsv = "#model_version:v2025.03.14,score_date:2026-10-14T12:55:00Z\ncve,epss,percentile\nCVE-2023-4863,0.93,0.99\nCVE-2024-1,0.01,0.3\n";

    private static byte[] Gzip(string text)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Fastest, leaveOpen: true))
            gz.Write(Encoding.UTF8.GetBytes(text));
        return ms.ToArray();
    }

    private static HttpResponseMessage Ok(byte[] body, string etag, string mediaType)
    {
        var r = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };
        r.Content.Headers.ContentType = new MediaTypeHeaderValue(mediaType);
        r.Headers.ETag = new EntityTagHeaderValue($"\"{etag}\"");
        return r;
    }

    private (StubHttpFactory Http, VulnFeedUpdater Updater) Build(ISecretStore? secrets = null)
    {
        var osvZip = TempVuln.BuildZip("debian-cve-2023-4863.json", "debian-cve-nofix.json");
        var http = new StubHttpFactory(req =>
        {
            var url = req.RequestUri!.ToString();
            if (req.Headers.TryGetValues("If-None-Match", out var inm) && inm.Any(v => v.Contains("v1")))
                return new HttpResponseMessage(HttpStatusCode.NotModified);
            if (url.EndsWith("/Debian/all.zip")) return Ok(osvZip, "v1", "application/zip");
            if (url.Contains("known_exploited")) return Ok(Encoding.UTF8.GetBytes(KevJson), "v1", "application/json");
            if (url.Contains("epss_scores")) return Ok(Gzip(EpssCsv), "v1", "application/gzip");
            if (url.Contains("cves/2.0"))
            {
                var cve = Uri.UnescapeDataString(req.RequestUri.Query.Split("cveId=")[1]);
                var body = cve switch
                {
                    "CVE-2023-4863" => """{"vulnerabilities":[{"cve":{"id":"CVE-2023-4863","metrics":{"cvssMetricV31":[{"type":"Secondary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L","baseScore":5.0}},{"type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H","baseScore":8.8}}]}}}]}""",
                    "CVE-2024-99999" => """{"vulnerabilities":[{"cve":{"id":"CVE-2024-99999","metrics":{}}}]}""",
                    _ => """{"vulnerabilities":[]}""",
                };
                return Ok(Encoding.UTF8.GetBytes(body), "n", "application/json");
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });
        var updater = new VulnFeedUpdater(_t.Db, Microsoft.Extensions.Options.Options.Create(_t.Options), http, secrets);
        return (http, updater);
    }

    [Fact]
    public async Task Update_BaixaProcessaEUsaDownloadCondicional()
    {
        var (http, updater) = Build();
        await updater.UpdateAsync([Deb12], default);

        var status = (await updater.GetStatusAsync(default)).ToDictionary(s => s.Name);
        Assert.True(status["osv:Debian:12"].Records >= 5);
        Assert.Equal(2, status["kev"].Records);
        Assert.Equal(2, status["epss"].Records);
        Assert.All(status.Values.Where(s => s.Name != "nvd"), s => { Assert.NotNull(s.UpdatedAt); Assert.Null(s.LastError); });
        Assert.Equal(0, status["nvd"].Records);
        Assert.Equal(3, http.Requests.Count);

        // segunda rodada: servidor responde 304, nada é reprocessado e o estado continua saudável
        await updater.UpdateAsync([Deb12], default);
        Assert.Equal(6, http.Requests.Count);
        Assert.All(http.Requests.Skip(3), r => Assert.True(r.Headers.Contains("If-None-Match")));
        status = (await updater.GetStatusAsync(default)).ToDictionary(s => s.Name);
        Assert.True(status["osv:Debian:12"].Records >= 5);
        Assert.Null(status["kev"].LastError);
    }

    [Fact]
    public async Task Update_NovoEcossistemaReprocessaZipEmCache()
    {
        var (http, updater) = Build();
        await updater.UpdateAsync([Deb12], default);
        await updater.UpdateAsync([Deb12, new OsInfo(Distro.Debian, "13", "trixie", "Debian 13")], default);

        var status = (await updater.GetStatusAsync(default)).ToDictionary(s => s.Name);
        Assert.True(status.ContainsKey("osv:Debian:13"));
        Assert.Equal(5, status["osv:Debian:13"].Records); // chromium, firefox-esr, libwebp, thunderbird e exampled (corrigido em 2.0-1)
    }

    [Fact]
    public async Task Update_FalhaNoFeedRegistraErroENaoImpedeOutros()
    {
        var http = new StubHttpFactory(req => req.RequestUri!.ToString().Contains("known_exploited")
            ? Ok(Encoding.UTF8.GetBytes(KevJson), "k", "application/json")
            : new HttpResponseMessage(HttpStatusCode.InternalServerError));
        var updater = new VulnFeedUpdater(_t.Db, Microsoft.Extensions.Options.Options.Create(_t.Options), http);

        await Assert.ThrowsAsync<AggregateException>(() => updater.UpdateAsync([Deb12], default));

        var status = (await updater.GetStatusAsync(default)).ToDictionary(s => s.Name);
        Assert.NotNull(status["osv:Debian:12"].LastError);
        Assert.NotNull(status["epss"].LastError);
        Assert.Null(status["kev"].LastError);
        Assert.Equal(2, status["kev"].Records);
    }

    [Fact]
    public async Task Fluxo_Completo_Update_Enrich_Match()
    {
        var (_, updater) = Build();
        await updater.UpdateAsync([Deb12], default);

        var scan = new HostScan(Deb12, "6.1", [new("libwebp7", "libwebp", "1.2.2-2", "1.2.2-2", "amd64")], [], false, DateTimeOffset.UtcNow);
        var matcher = new VulnerabilityMatcher(_t.Db);
        var before = Assert.Single(await matcher.MatchAsync(scan, new SeverityThresholds(), default));
        Assert.True(before.Kev);
        Assert.Equal(0.93, before.Epss);
        Assert.Equal(Severity.Critical, before.Severity);

        await updater.EnrichAsync(["CVE-2023-4863", "CVE-2024-99999", "lixo"], default);
        var after = Assert.Single(await matcher.MatchAsync(scan, new SeverityThresholds(), default));
        Assert.Equal(8.8, after.Cvss); // Primary vence Secondary
        Assert.Equal("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", after.CvssVector);

        var nvd = (await updater.GetStatusAsync(default)).Single(s => s.Name == "nvd");
        Assert.Equal(1, nvd.Records); // o sem nota fica em cache mas não conta
    }

    [Fact]
    public async Task Enrich_UsaApiKeyDoCofre_ESegueSemKeyQuandoCofreFalha()
    {
        var (http, updater) = Build(new FakeSecrets(new Dictionary<string, string> { [SecretPaths.ApiKey] = "k-123" }));
        await updater.EnrichAsync(["CVE-2023-4863"], default);
        var req = Assert.Single(http.Requests);
        Assert.Equal("k-123", req.Headers.GetValues("apiKey").Single());

        var (http2, updater2) = Build(new FakeSecrets(null));
        await updater2.EnrichAsync(["CVE-2023-4864"], default);
        Assert.Single(http2.Requests);
        Assert.False(http2.Requests[0].Headers.Contains("apiKey"));
    }

    [Fact]
    public async Task Enrich_NaoRepeteConsultasEmCache_EFalhaIndividualNaoDerrubaLote()
    {
        var calls = 0;
        var http = new StubHttpFactory(req =>
        {
            calls++;
            return req.RequestUri!.Query.Contains("CVE-2024-0002")
                ? new HttpResponseMessage(HttpStatusCode.BadGateway)
                : Ok(Encoding.UTF8.GetBytes("""{"vulnerabilities":[{"cve":{"metrics":{"cvssMetricV30":[{"type":"Primary","cvssData":{"version":"3.0","vectorString":"CVSS:3.0/AV:N","baseScore":7.5}}]}}}]}"""), "n", "application/json");
        });
        var opts = _t.Options;
        opts.NvdWindow = TimeSpan.FromMilliseconds(50);
        var updater = new VulnFeedUpdater(_t.Db, Microsoft.Extensions.Options.Options.Create(opts), http);

        await updater.EnrichAsync(["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"], default);
        Assert.Equal(3, calls);
        await updater.EnrichAsync(["CVE-2024-0001", "CVE-2024-0003"], default);
        Assert.Equal(3, calls);

        var nvd = (await updater.GetStatusAsync(default)).Single(s => s.Name == "nvd");
        Assert.Equal(2, nvd.Records);
        Assert.NotNull(nvd.LastError);
    }

    [Fact]
    public async Task Enrich_RespeitaRateLimit()
    {
        var http = new StubHttpFactory(_ => Ok(Encoding.UTF8.GetBytes("""{"vulnerabilities":[]}"""), "n", "application/json"));
        var opts = _t.Options;
        opts.NvdWindow = TimeSpan.FromMilliseconds(400);
        opts.NvdRequestsWithoutKey = 2;
        var updater = new VulnFeedUpdater(_t.Db, Microsoft.Extensions.Options.Options.Create(opts), http);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        await updater.EnrichAsync(["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004", "CVE-2024-0005"], default);
        sw.Stop();
        Assert.Equal(5, http.Requests.Count);
        Assert.True(sw.Elapsed >= TimeSpan.FromMilliseconds(750), $"sem espera suficiente: {sw.Elapsed}");
    }

    [Fact]
    public void AddPvePatcherVuln_RegistraServicosELeOpcoes()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Vuln:DatabasePath"] = Path.Combine(_t.Dir, "di.db"),
            ["Vuln:CacheDir"] = Path.Combine(_t.Dir, "di-feeds"),
        }).Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddPvePatcherVuln(config);
        using var sp = services.BuildServiceProvider();

        Assert.IsType<VulnerabilityMatcher>(sp.GetRequiredService<IVulnerabilityMatcher>());
        Assert.IsType<VulnFeedUpdater>(sp.GetRequiredService<IVulnFeedUpdater>());
        Assert.Equal(Path.Combine(_t.Dir, "di.db"), sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<VulnOptions>>().Value.DatabasePath);
    }

    [Fact]
    public void OpcoesPadrao()
    {
        var o = new VulnOptions();
        Assert.Equal("/var/lib/pve-patcher/vuln.db", o.DatabasePath);
        Assert.Equal("/var/lib/pve-patcher/feeds", o.CacheDir);
    }

    private sealed class FakeSecrets(Dictionary<string, string>? data) : ISecretStore
    {
        public Task<VaultStatus> GetStatusAsync(CancellationToken ct) => Task.FromResult(new VaultStatus(VaultState.Ready, null));

        public Task<IReadOnlyDictionary<string, string>?> ReadAsync(string path, CancellationToken ct)
        {
            Assert.Equal(SecretPaths.Nvd, path);
            if (data is null) throw new VaultUnavailableException(new VaultStatus(VaultState.Sealed, null));
            return Task.FromResult<IReadOnlyDictionary<string, string>?>(data);
        }

        public Task WriteAsync(string path, IReadOnlyDictionary<string, string> d, CancellationToken ct) => Task.CompletedTask;
        public Task DeleteAsync(string path, CancellationToken ct) => Task.CompletedTask;
    }
}

/// <summary>Validação manual contra os dumps reais (rede, centenas de MB): rode removendo o Skip.</summary>
public class RealDataTests
{
    [Fact(Skip = "Manual: baixa o dump real do OSV (Debian ~76 MB). Validado em 2026-10-14.")]
    public async Task Debian12_DumpReal_ParseiaSemErros()
    {
        using var t = new TempVuln();
        var factory = new StubHttpFactory(_ => throw new InvalidOperationException());
        var http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        var zipPath = Path.Combine(t.Dir, "Debian.zip");
        await File.WriteAllBytesAsync(zipPath, await http.GetByteArrayAsync("https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip"));

        var updater = new VulnFeedUpdater(t.Db, Microsoft.Extensions.Options.Options.Create(t.Options), factory);
        var counts = updater.IngestZip(zipPath, new HashSet<string> { "Debian:12" }, default);
        Assert.True(counts["Debian:12"] > 10_000);

        var scan = new HostScan(new OsInfo(Distro.Debian, "12", "bookworm", "Debian 12"), "6.1",
            [new("libssl3", "openssl", "3.0.0-1", "3.0.0-1", "amd64")], [], false, DateTimeOffset.UtcNow);
        var findings = await new VulnerabilityMatcher(t.Db).MatchAsync(scan, new SeverityThresholds(), default);
        Assert.NotEmpty(findings);
    }
}
