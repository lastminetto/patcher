using System.IO.Compression;
using Microsoft.Extensions.Options;
using PvePatcher.Core;

namespace PvePatcher.Vuln.Tests;

/// <summary>vuln.db temporário populado a partir das fixtures.</summary>
public sealed class TempVuln : IDisposable
{
    public string Dir { get; } = Path.Combine(Path.GetTempPath(), "pvepatcher-vuln-" + Guid.NewGuid().ToString("N"));
    public VulnOptions Options { get; }
    public VulnDatabase Db { get; }

    public TempVuln()
    {
        Directory.CreateDirectory(Dir);
        Options = new VulnOptions { DatabasePath = Path.Combine(Dir, "vuln.db"), CacheDir = Path.Combine(Dir, "feeds") };
        Db = new VulnDatabase(Microsoft.Extensions.Options.Options.Create(Options));
    }

    public static string FixturePath(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

    /// <summary>Cria um all.zip com as fixtures, nomeadas pelo id como no dump real.</summary>
    public static byte[] BuildZip(params string[] fixtures)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var f in fixtures)
            {
                var entry = zip.CreateEntry(Path.GetFileNameWithoutExtension(f).ToUpperInvariant().Replace("-2024-0010", "-2024:0010").Replace("-2024-0012", "-2024:0012") + ".json");
                using var s = entry.Open();
                s.Write(File.ReadAllBytes(FixturePath(f)));
            }
        }
        return ms.ToArray();
    }

    public void Ingest(string[] fixtures, params string[] ecosystems)
    {
        var zipPath = Path.Combine(Dir, Guid.NewGuid().ToString("N") + ".zip");
        File.WriteAllBytes(zipPath, BuildZip(fixtures));
        var updater = new VulnFeedUpdater(Db, Microsoft.Extensions.Options.Options.Create(Options), new StubHttpFactory(_ => new HttpResponseMessage(System.Net.HttpStatusCode.NotFound)));
        updater.IngestZip(zipPath, new HashSet<string>(ecosystems), CancellationToken.None);
    }

    public void Dispose()
    {
        try { Directory.Delete(Dir, recursive: true); } catch { /* arquivo ainda aberto: tudo bem em %TEMP% */ }
    }
}

public sealed class StubHttpFactory(Func<HttpRequestMessage, HttpResponseMessage> handler) : IHttpClientFactory
{
    public List<HttpRequestMessage> Requests { get; } = [];

    public HttpClient CreateClient(string name) => new(new Handler(this, handler), disposeHandler: true);

    private sealed class Handler(StubHttpFactory owner, Func<HttpRequestMessage, HttpResponseMessage> fn) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            lock (owner.Requests) owner.Requests.Add(request);
            return Task.FromResult(fn(request));
        }
    }
}

public class MatcherTests : IDisposable
{
    private readonly TempVuln _t = new();
    private static readonly SeverityThresholds Thr = new();

    public void Dispose() => _t.Dispose();

    private static HostScan Scan(OsInfo os, IEnumerable<InstalledPackage> installed, params PendingUpdate[] pending) =>
        new(os, "6.1.0", installed.ToList(), pending, false, DateTimeOffset.UtcNow);

    private static readonly OsInfo Deb12 = new(Distro.Debian, "12", "bookworm", "Debian 12");

    [Fact]
    public async Task Debian_CorrigidoPorAtualizacaoPendente_UsaNomeFonteEVersaoFonte()
    {
        _t.Ingest(["debian-cve-2023-4863.json", "debian-cve-nofix.json"], "Debian:12");
        var scan = Scan(Deb12,
            [
                new("libwebp7", "libwebp", "1.2.4-0.1", "1.2.2-2", "amd64"),
                new("firefox-esr", "firefox-esr", "115.0esr-1~deb12u1", "115.0esr-1~deb12u1", "amd64"),
                new("exampled", "exampled", "1.0-1", "1.0-1", "amd64"),
                new("bash", "bash", "5.2-1", "5.2-1", "amd64"),
            ],
            new PendingUpdate("libwebp7", "libwebp", "1.2.4-0.1", "1.2.4-0.2+deb12u1", "amd64", false));

        var findings = await new VulnerabilityMatcher(_t.Db).MatchAsync(scan, Thr, default);

        Assert.Equal(2, findings.Count);
        var webp = Assert.Single(findings, f => f.CveId == "CVE-2023-4863");
        Assert.Equal("libwebp7", webp.Package);
        Assert.Equal("libwebp", webp.SourcePackage);
        Assert.Equal("1.2.2-2", webp.InstalledVersion);
        Assert.Equal("1.2.4-0.2+deb12u1", webp.FixedVersion);
        Assert.Equal("1.2.4-0.2+deb12u1", webp.CandidateVersion);
        Assert.Equal(FindingStatus.FixedByPendingUpdate, webp.Status);
        Assert.Null(webp.AdvisoryId);
        Assert.Equal(8.8, webp.Cvss);
        Assert.Equal(Severity.High, webp.Severity);
        Assert.Null(webp.DistroSeverity);

        var open = Assert.Single(findings, f => f.CveId == "CVE-2024-99999");
        Assert.Equal(FindingStatus.Unfixed, open.Status);
        Assert.Null(open.FixedVersion);
        Assert.Equal(Severity.Low, open.Severity); // sem CVSS: urgência "low" da distro
    }

    [Fact]
    public async Task Debian_CorrecaoForaDaCandidata()
    {
        _t.Ingest(["debian-cve-2023-4863.json"], "Debian:12");
        var scan = Scan(Deb12,
            [new("libwebp7", "libwebp", "1.2.2-2", "1.2.2-2", "amd64")],
            new PendingUpdate("libwebp7", "libwebp", "1.2.2-2", "1.2.2-3", "amd64", false));

        var f = Assert.Single(await new VulnerabilityMatcher(_t.Db).MatchAsync(scan, Thr, default));
        Assert.Equal(FindingStatus.FixNotInCandidate, f.Status);
        Assert.Equal("1.2.2-3", f.CandidateVersion);

        var semPendente = Scan(Deb12, [new("libwebp7", "libwebp", "1.2.2-2", "1.2.2-2", "amd64")]);
        f = Assert.Single(await new VulnerabilityMatcher(_t.Db).MatchAsync(semPendente, Thr, default));
        Assert.Equal(FindingStatus.FixNotInCandidate, f.Status);
        Assert.Null(f.CandidateVersion);
    }

    [Fact]
    public async Task Debian_VersaoJaCorrigida_NaoGeraFinding()
    {
        _t.Ingest(["debian-cve-2023-4863.json"], "Debian:12");
        var scan = Scan(Deb12, [new("libwebp7", "libwebp", "1.2.4-0.2+deb12u1+b1", "1.2.4-0.2+deb12u1", "amd64")]);
        Assert.Empty(await new VulnerabilityMatcher(_t.Db).MatchAsync(scan, Thr, default));
    }

    [Fact]
    public async Task Debian_AvisoDsa_PreencheAdvisoryIdEUmFindingPorBinarioECve()
    {
        _t.Ingest(["dsa-5000-1.json"], "Debian:11");
        var scan = Scan(new OsInfo(Distro.Debian, "11", "bullseye", "Debian 11"),
            [
                new("openjdk-11-jre", "openjdk-11", "11.0.12+7-2", "11.0.12+7-2", "amd64"),
                new("openjdk-11-jdk", "openjdk-11", "11.0.12+7-2", "11.0.12+7-2", "amd64"),
            ],
            new PendingUpdate("openjdk-11-jre", "openjdk-11", "11.0.12+7-2", "11.0.13+8-1~deb11u1", "amd64", false));

        var findings = await new VulnerabilityMatcher(_t.Db).MatchAsync(scan, Thr, default);
        Assert.Equal(20, findings.Count);
        Assert.All(findings, f => Assert.Equal("DSA-5000-1", f.AdvisoryId));
        Assert.Equal(10, findings.Count(f => f.Package == "openjdk-11-jre" && f.Status == FindingStatus.FixedByPendingUpdate));
        Assert.Equal(10, findings.Count(f => f.Package == "openjdk-11-jdk" && f.Status == FindingStatus.FixNotInCandidate));
        Assert.Equal(20, findings.Select(f => (f.CveId, f.Package)).Distinct().Count());
    }

    [Fact]
    public async Task Alma_PorNomeBinario_SeveridadeDoAviso()
    {
        _t.Ingest(["alsa-2024-0010.json"], "AlmaLinux:9");
        var scan = Scan(new OsInfo(Distro.AlmaLinux, "9.3", null, "AlmaLinux 9.3"),
            [
                new("tigervnc-server", "tigervnc", "1.13.1-3.el9_3.2.alma.1", "1.13.1-3.el9_3.2.alma.1", "x86_64"),
                new("bash", "bash", "5.1.8-9.el9", "5.1.8-9.el9", "x86_64"),
            ],
            new PendingUpdate("tigervnc-server", "tigervnc", "1.13.1-3.el9_3.2.alma.1", "1.13.1-3.el9_3.3.alma.1", "x86_64", false));

        var findings = await new VulnerabilityMatcher(_t.Db).MatchAsync(scan, Thr, default);
        Assert.Equal(["CVE-2023-5367", "CVE-2023-6377", "CVE-2023-6478"], findings.Select(f => f.CveId).Order());
        Assert.All(findings, f =>
        {
            Assert.Equal("ALSA-2024:0010", f.AdvisoryId);
            Assert.Equal(FindingStatus.FixedByPendingUpdate, f.Status);
            Assert.Equal("Important", f.DistroSeverity);
            Assert.Equal(Severity.High, f.Severity);
            Assert.Equal("1.13.1-3.el9_3.2.alma.1", f.InstalledVersion);
        });
    }

    [Fact]
    public async Task Rocky_FixedComEpoch()
    {
        _t.Ingest(["rlsa-2024-0012.json"], "Rocky Linux:8");
        var scan = Scan(new OsInfo(Distro.Rocky, "8.9", null, "Rocky 8.9"),
            [new("firefox", "firefox", "115.5.0-1.el8_9", "115.5.0-1.el8_9", "x86_64")]);
        var findings = await new VulnerabilityMatcher(_t.Db).MatchAsync(scan, Thr, default);
        Assert.Equal(11, findings.Count);
        Assert.All(findings, f => Assert.Equal("RLSA-2024:0012", f.AdvisoryId));
    }

    [Fact]
    public async Task Alpine_PorOrigin()
    {
        _t.Ingest(["alpine-cve-2024-0553.json"], "Alpine:v3.20");
        var os = new OsInfo(Distro.Alpine, "3.20.3", null, "Alpine 3.20");
        var vulneravel = Scan(os, [new("libgnutls", "gnutls", "3.8.2-r0", "3.8.2-r0", "x86_64")]);
        var f = Assert.Single(await new VulnerabilityMatcher(_t.Db).MatchAsync(vulneravel, Thr, default));
        Assert.Equal(("CVE-2024-0553", "libgnutls", "gnutls", "3.8.3-r0"), (f.CveId, f.Package, f.SourcePackage, f.FixedVersion));
        Assert.Equal((7.5, Severity.High), (f.Cvss, f.Severity)); // vetor CVSS_V3 do próprio registro OSV

        var ok = Scan(os, [new("libgnutls", "gnutls", "3.8.3-r0", "3.8.3-r0", "x86_64")]);
        Assert.Empty(await new VulnerabilityMatcher(_t.Db).MatchAsync(ok, Thr, default));
    }

    [Fact]
    public async Task Ubuntu_SemCorrecao_UsaSeveridadeDaDistroEEcossistemaLts()
    {
        _t.Ingest(["ubuntu-cve-2024-0046.json"], "Ubuntu:24.04:LTS");
        var scan = Scan(new OsInfo(Distro.Ubuntu, "24.04", "noble", "Ubuntu 24.04"),
            [new("aapt", "android-platform-frameworks-base", "1:6.0.1+r16-1", "1:6.0.1+r16-1", "amd64")]);
        var findings = await new VulnerabilityMatcher(_t.Db).MatchAsync(scan, Thr, default);
        var f = Assert.Single(findings);
        Assert.Equal((FindingStatus.Unfixed, "medium", 7.8, Severity.High), (f.Status, f.DistroSeverity, f.Cvss, f.Severity));
    }

    [Fact]
    public async Task EcossistemaSemDados_OuSoDesconhecido_Vazio()
    {
        var scan = Scan(Deb12, [new("bash", "bash", "5.2-1", "5.2-1", null)]);
        Assert.Empty(await new VulnerabilityMatcher(_t.Db).MatchAsync(scan, Thr, default));
        var unknown = Scan(new OsInfo(Distro.Unknown, "1", null, "x"), [new("bash", "bash", "5", "5", null)]);
        Assert.Empty(await new VulnerabilityMatcher(_t.Db).MatchAsync(unknown, Thr, default));
    }

    [Fact]
    public async Task KevEpssENvd_AlteramSeveridade()
    {
        _t.Ingest(["debian-cve-2023-4863.json"], "Debian:12");
        var scan = Scan(Deb12, [new("libwebp7", "libwebp", "1.2.2-2", "1.2.2-2", "amd64")]);
        var matcher = new VulnerabilityMatcher(_t.Db);

        using (var conn = _t.Db.Open())
        {
            VulnDatabase.Exec(conn, "INSERT INTO epss(cve_id,score) VALUES('CVE-2023-4863',0.93)");
        }
        var f = Assert.Single(await matcher.MatchAsync(scan, Thr, default));
        Assert.Equal(0.93, f.Epss);
        Assert.Equal(Severity.High, f.Severity);
        Assert.False(f.Kev);

        using (var conn = _t.Db.Open())
        {
            VulnDatabase.Exec(conn, "INSERT INTO kev(cve_id) VALUES('CVE-2023-4863')");
            VulnDatabase.Exec(conn, "INSERT INTO nvd_cache(cve_id,cvss,vector,version,fetched_at) VALUES('CVE-2023-4863',9.6,'CVSS:3.1/AV:N','3.1','2024-01-01')");
        }
        f = Assert.Single(await matcher.MatchAsync(scan, Thr, default));
        Assert.True(f.Kev);
        Assert.Equal(9.6, f.Cvss);
        Assert.Equal("CVSS:3.1/AV:N", f.CvssVector);
        Assert.Equal(Severity.Critical, f.Severity);
    }

    [Theory]
    [InlineData(null, false, null, null, Severity.Unknown)]
    [InlineData(null, false, null, "Important", Severity.High)]
    [InlineData(null, false, null, "moderate", Severity.Medium)]
    [InlineData(null, false, null, "negligible", Severity.Low)]
    [InlineData(null, false, null, "unimportant", Severity.Low)]
    [InlineData(null, false, null, "critical", Severity.Critical)]
    [InlineData(null, true, null, null, Severity.Critical)]
    [InlineData(2.0, true, null, null, Severity.Critical)]
    [InlineData(9.0, false, null, null, Severity.Critical)]
    [InlineData(8.9, false, null, null, Severity.High)]
    [InlineData(7.0, false, null, null, Severity.High)]
    [InlineData(3.0, false, 0.5, null, Severity.High)]
    [InlineData(6.9, false, 0.49, null, Severity.Medium)]
    [InlineData(4.0, false, null, null, Severity.Medium)]
    [InlineData(3.9, false, 0.1, "high", Severity.Low)]
    [InlineData(0.0, false, null, null, Severity.Low)]
    [InlineData(null, false, 0.7, "low", Severity.High)]
    public void Classify(double? cvss, bool kev, double? epss, string? distro, Severity expected)
    {
        Assert.Equal(expected, VulnerabilityMatcher.Classify(cvss, kev, epss, distro, Thr));
    }

    [Fact]
    public async Task Desempenho_1500PacotesComBancoGrande()
    {
        using (var conn = _t.Db.Open())
        using (var tx = conn.BeginTransaction())
        {
            using var r = conn.CreateCommand();
            r.Transaction = tx;
            r.CommandText = "INSERT INTO osv_range(ecosystem,pkg,vuln_id,introduced,fixed,last_affected,severity) VALUES('Debian:12',@p,@v,NULL,@f,NULL,'low')";
            var p = r.Parameters.Add("@p", Microsoft.Data.Sqlite.SqliteType.Text);
            var v = r.Parameters.Add("@v", Microsoft.Data.Sqlite.SqliteType.Text);
            var f = r.Parameters.Add("@f", Microsoft.Data.Sqlite.SqliteType.Text);
            using var vul = conn.CreateCommand();
            vul.Transaction = tx;
            vul.CommandText = "INSERT INTO osv_vuln(vuln_id,is_advisory,summary) VALUES(@v,0,'x')";
            var vv = vul.Parameters.Add("@v", Microsoft.Data.Sqlite.SqliteType.Text);
            using var al = conn.CreateCommand();
            al.Transaction = tx;
            al.CommandText = "INSERT INTO osv_alias(vuln_id,cve_id) VALUES(@v,@c)";
            var av = al.Parameters.Add("@v", Microsoft.Data.Sqlite.SqliteType.Text);
            var ac = al.Parameters.Add("@c", Microsoft.Data.Sqlite.SqliteType.Text);
            for (var i = 0; i < 300_000; i++)
            {
                var id = $"DEBIAN-CVE-2020-{i:D6}";
                vv.Value = id; vul.ExecuteNonQuery();
                av.Value = id; ac.Value = $"CVE-2020-{i:D6}"; al.ExecuteNonQuery();
                p.Value = $"pkg{i % 50000}"; v.Value = id; f.Value = $"{1 + i % 7}.0-1"; r.ExecuteNonQuery();
            }
            tx.Commit();
        }

        var installed = Enumerable.Range(0, 1500).Select(i => new InstalledPackage($"pkg{i}-bin", $"pkg{i}", "0.5-1", "0.5-1", "amd64")).ToList();
        var matcher = new VulnerabilityMatcher(_t.Db);
        var scan = Scan(Deb12, installed);
        await matcher.MatchAsync(scan, Thr, default); // aquece

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var findings = await matcher.MatchAsync(scan, Thr, default);
        sw.Stop();

        Assert.Equal(300_000 / 50_000 * 1500, findings.Count);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2), $"match levou {sw.Elapsed}");
    }
}
