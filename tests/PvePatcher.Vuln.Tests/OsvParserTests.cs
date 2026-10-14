using System.Text;
using PvePatcher.Core;

namespace PvePatcher.Vuln.Tests;

public class CvssTests
{
    [Theory]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8)]
    [InlineData("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8)]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8)]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0)]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1)]
    [InlineData("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5)]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0)]
    public void ScoreV3(string vector, double expected) => Assert.Equal(expected, Cvss.ScoreV3(vector));

    [Fact]
    public void ScoreV3_IgnoraV4EVetorInvalido()
    {
        Assert.Null(Cvss.ScoreV3("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"));
        Assert.Null(Cvss.ScoreV3("lixo"));
        Assert.Null(Cvss.ScoreV3(null));
    }
}

public class OsvParserTests
{
    private static ReadOnlyMemory<byte> Fixture(string name) =>
        File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    [Fact]
    public void DebianDsa_ComUpstreamEFixed()
    {
        var rec = OsvParser.Parse(Fixture("dsa-5000-1.json"), e => e == "Debian:11")!;
        Assert.Equal("DSA-5000-1", rec.Id);
        Assert.True(rec.IsAdvisory);
        Assert.Equal(10, rec.CveIds.Count); // CVE-* e DEBIAN-CVE-* colapsam
        Assert.Contains("CVE-2021-35550", rec.CveIds);
        Assert.DoesNotContain(rec.CveIds, c => c.StartsWith("DEBIAN"));
        var range = Assert.Single(rec.Ranges);
        Assert.Equal("openjdk-11", range.Package);
        Assert.Null(range.Introduced);
        Assert.Equal("11.0.13+8-1~deb11u1", range.Fixed);
        Assert.Equal("openjdk-11 - security update", rec.Summary);
    }

    [Fact]
    public void EcossistemaNaoSolicitado_Ignorado()
    {
        Assert.Null(OsvParser.Parse(Fixture("dsa-5000-1.json"), e => e == "Debian:12"));
    }

    [Fact]
    public void DebianCve_FiltraPorEcossistemaEExtraiUrgencia()
    {
        var rec = OsvParser.Parse(Fixture("debian-cve-2023-4863.json"), e => e == "Debian:12")!;
        Assert.False(rec.IsAdvisory);
        Assert.Equal(["CVE-2023-4863"], rec.CveIds);
        Assert.Equal(4, rec.Ranges.Count);
        Assert.All(rec.Ranges, r => Assert.Equal("Debian:12", r.Ecosystem));
        Assert.Equal("unimportant", rec.Ranges.Single(r => r.Package == "chromium").DistroSeverity);
        Assert.Null(rec.Ranges.Single(r => r.Package == "libwebp").DistroSeverity); // "not yet assigned"
        Assert.Contains(rec.Ranges, r => r.Package == "libwebp" && r.Fixed == "1.2.4-0.2+deb12u1");
        Assert.Contains(rec.Ranges, r => r.Package == "thunderbird" && r.Fixed == "1:102.15.1-1~deb12u1");
        Assert.StartsWith("Heap buffer overflow", rec.Summary);
        Assert.StartsWith("CVSS:3.1/", rec.CvssVector);
        Assert.Equal(8.8, rec.CvssScore);
    }

    [Fact]
    public void DebianCve_SemFixed()
    {
        var rec = OsvParser.Parse(Fixture("debian-cve-nofix.json"), e => e == "Debian:12")!;
        var r = Assert.Single(rec.Ranges);
        Assert.Equal("exampled", r.Package);
        Assert.Null(r.Introduced);
        Assert.Null(r.Fixed);
        Assert.Null(r.LastAffected);
        Assert.Equal("low", r.DistroSeverity);
        Assert.Equal("Integer overflow in exampled before 2.0 allows remote attackers to crash the daemon.", rec.Summary);
    }

    [Fact]
    public void Alsa_PacotesBinariosCvesEmRelatedESeveridadeDoSummary()
    {
        var rec = OsvParser.Parse(Fixture("alsa-2024-0010.json"), e => e == "AlmaLinux:9")!;
        Assert.True(rec.IsAdvisory);
        Assert.Equal(["CVE-2023-5367", "CVE-2023-6377", "CVE-2023-6478"], rec.CveIds);
        Assert.Equal(7, rec.Ranges.Count);
        Assert.Contains(rec.Ranges, r => r.Package == "tigervnc-server");
        Assert.All(rec.Ranges, r => Assert.Equal("1.13.1-3.el9_3.3.alma.1", r.Fixed));
        Assert.All(rec.Ranges, r => Assert.Equal("Important", r.DistroSeverity));
    }

    [Fact]
    public void Rlsa_UpstreamEEpochNoFixed()
    {
        var rec = OsvParser.Parse(Fixture("rlsa-2024-0012.json"), e => e == "Rocky Linux:8")!;
        Assert.Equal(11, rec.CveIds.Count);
        Assert.Contains(rec.Ranges, r => r.Package == "firefox" && r.Fixed == "0:115.6.0-1.el8_9");
    }

    [Fact]
    public void Alpine_UmaLinhaPorRelease()
    {
        var rec = OsvParser.Parse(Fixture("alpine-cve-2024-0553.json"), e => e == "Alpine:v3.20")!;
        Assert.Equal(["CVE-2024-0553"], rec.CveIds);
        var r = Assert.Single(rec.Ranges);
        Assert.Equal(("gnutls", "3.8.3-r0"), (r.Package, r.Fixed));
        Assert.Null(r.DistroSeverity);
    }

    [Fact]
    public void Ubuntu_SeveridadeDeTopoEEcossistemaComLts()
    {
        var rec = OsvParser.Parse(Fixture("ubuntu-cve-2024-0046.json"), e => e == "Ubuntu:24.04:LTS")!;
        Assert.Equal(["CVE-2024-0046"], rec.CveIds);
        Assert.Equal(2, rec.Ranges.Count);
        Assert.All(rec.Ranges, r => { Assert.Equal("medium", r.DistroSeverity); Assert.Null(r.Fixed); });
        Assert.Equal(7.8, rec.CvssScore);
    }

    [Fact]
    public void SemCve_OuRetirado_Ignorado()
    {
        const string alba = """{"id":"ALBA-2024:1","summary":"bugfix","affected":[{"package":{"name":"x","ecosystem":"AlmaLinux:9"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1-1"}]}]}]}""";
        Assert.Null(OsvParser.Parse(Encoding.UTF8.GetBytes(alba), _ => true));
        const string withdrawn = """{"id":"CVE-2024-1","withdrawn":"2024-01-01T00:00:00Z","affected":[{"package":{"name":"x","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}""";
        Assert.Null(OsvParser.Parse(Encoding.UTF8.GetBytes(withdrawn), _ => true));
    }

    [Fact]
    public void VariasFaixasNoMesmoRange()
    {
        const string json = """
            {"id":"CVE-2024-5555","affected":[{"package":{"name":"p","ecosystem":"Alpine:v3.20"},"ranges":[{"type":"ECOSYSTEM","events":[
              {"introduced":"1.0"},{"fixed":"1.5-r0"},{"introduced":"2.0"},{"last_affected":"2.3-r1"},{"introduced":"3.0"}]}]}]}
            """;
        var rec = OsvParser.Parse(Encoding.UTF8.GetBytes(json), _ => true)!;
        Assert.Equal(3, rec.Ranges.Count);
        Assert.Equal(("1.0", "1.5-r0", null), (rec.Ranges[0].Introduced, rec.Ranges[0].Fixed, rec.Ranges[0].LastAffected));
        Assert.Equal(("2.0", null, "2.3-r1"), (rec.Ranges[1].Introduced, rec.Ranges[1].Fixed, rec.Ranges[1].LastAffected));
        Assert.Equal(("3.0", null, null), (rec.Ranges[2].Introduced, rec.Ranges[2].Fixed, rec.Ranges[2].LastAffected));
    }

    [Theory]
    [InlineData(Distro.Debian, "12", "bookworm", "Debian:12")]
    [InlineData(Distro.Debian, "12.5", null, "Debian:12")]
    [InlineData(Distro.Debian, "", "trixie", "Debian:13")]
    [InlineData(Distro.Ubuntu, "24.04", "noble", "Ubuntu:24.04:LTS")]
    [InlineData(Distro.Ubuntu, "22.04", null, "Ubuntu:22.04:LTS")]
    [InlineData(Distro.Ubuntu, "23.10", null, "Ubuntu:23.10")]
    [InlineData(Distro.Ubuntu, "25.04", null, "Ubuntu:25.04")]
    [InlineData(Distro.AlmaLinux, "9.4", null, "AlmaLinux:9")]
    [InlineData(Distro.Rocky, "9.3", null, "Rocky Linux:9")]
    [InlineData(Distro.Alpine, "3.20.3", null, "Alpine:v3.20")]
    public void EcossistemaOsv(Distro distro, string version, string? codename, string expected)
    {
        Assert.Equal(expected, OsvEcosystems.FromOs(new OsInfo(distro, version, codename, "x")));
    }

    [Fact]
    public void EcossistemaOsv_Desconhecido()
    {
        Assert.Null(OsvEcosystems.FromOs(new OsInfo(Distro.Unknown, "1", null, "x")));
    }
}
