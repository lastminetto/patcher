using PvePatcher.Vuln.Versioning;

namespace PvePatcher.Vuln.Tests;

public class DpkgVersionComparerTests
{
    private static readonly DpkgVersionComparer C = DpkgVersionComparer.Instance;

    // (a, b, sinal esperado de Compare(a, b)); no estilo da suíte do dpkg (Dpkg_Version.t / t-version.c)
    public static TheoryData<string, string, int> Vectors => new()
    {
        { "1.0", "1.0", 0 },
        { "1.0", "1.1", -1 },
        { "1.1", "1.0", 1 },
        { "1.0-1", "1.0-2", -1 },
        { "1.0-1", "1.0-1", 0 },
        { "1.0", "1.0-0", 0 },
        { "0", "0-0", 0 },
        { "0", "00", 0 },
        { "1.01", "1.1", 0 },
        { "1.009", "1.9", 0 },
        { "1.10", "1.9", 1 },
        { "1.9", "1.10", -1 },
        { "0:1.0", "1.0", 0 },
        { "1:0.1", "2.0", 1 },
        { "1:1.0", "0:99.9", 1 },
        { "0:0", "1:0", -1 },
        { "2:1.0", "1:9.9", 1 },
        { "1.0~rc1", "1.0", -1 },
        { "1.0~rc1", "1.0~rc2", -1 },
        { "1.0~rc1", "1.0~rc1", 0 },
        { "1.0~", "1.0", -1 },
        { "1.0~~", "1.0~", -1 },
        { "1.0~~a", "1.0~~", 1 },
        { "1.0~~a", "1.0~", -1 },
        { "1.0~rc1", "1.0~", 1 },
        { "1.0a", "1.0", 1 },
        { "1.0", "1.0a", -1 },
        { "1.0a", "1.0b", -1 },
        { "1.0+", "1.0", 1 },
        { "1.0a", "1.0+", -1 },
        { "1.0-", "1.0", 0 },
        { "1.0.1", "1.0", 1 },
        { "2.0", "2.0.0", -1 },
        { "a", "1", 1 },
        { "1", "a", -1 },
        { "a", "b", -1 },
        { "1.0-1ubuntu1", "1.0-1", 1 },
        { "1.0-1ubuntu1", "1.0-1ubuntu2", -1 },
        { "1.0-1~bpo12+1", "1.0-1", -1 },
        { "2.0-1+deb12u1", "2.0-1", 1 },
        { "7.88.1-10+deb12u5", "7.88.1-10+deb12u12", -1 },
        { "7.88.1-10+deb12u12", "7.88.1-10+deb12u5", 1 },
        { "1.2.3-1+b1", "1.2.3-1", 1 },
        { "1.2.3-1", "1.2.3-1+b1", -1 },
        { "1.0-0.1", "1.0-1", -1 },
        { "1.0-0ubuntu0.22.04.1", "1.0-0ubuntu0.22.04.2", -1 },
        { "3.0.11-1~deb12u2", "3.0.11-1~deb12u1", 1 },
        { "3.0.11-1~deb12u2", "3.0.11-1", -1 },
        { "1:102.15.1-1~deb12u1", "1:102.15.1-1~deb12u1", 0 },
        { "102.15.1esr-1~deb12u1", "115.0esr-1", -1 },
        { "0:0-0-0", "0-0-0", 0 },
        { "0:0.0-0.0", "0.0-0.0", 0 },
        { "5.10.0-1~bpo10+1", "5.10.0-1", -1 },
        { "2.36-9+deb12u7", "2.36-9+deb12u10", -1 },
        { "1.0:2", "1.0:3", -1 },
    };

    [Theory, MemberData(nameof(Vectors))]
    public void Compare(string a, string b, int expected)
    {
        Assert.Equal(expected, Math.Sign(C.Compare(a, b)));
        Assert.Equal(-expected, Math.Sign(C.Compare(b, a)));
    }

    [Fact]
    public void Parse_UsaPrimeiroDoisPontosEUltimoHifen()
    {
        Assert.Equal((0L, "0", ""), DpkgVersionComparer.Parse("0"));
        Assert.Equal((5L, "1", ""), DpkgVersionComparer.Parse("5:1"));
        Assert.Equal((0L, "0-0", "0"), DpkgVersionComparer.Parse("0:0-0-0"));
        Assert.Equal((0L, "0-0-0", "0"), DpkgVersionComparer.Parse("0:0-0-0-0"));
        Assert.Equal((0L, "0:0", "0"), DpkgVersionComparer.Parse("0:0:0-0"));
        Assert.Equal((0L, "0:0:0", "0"), DpkgVersionComparer.Parse("0:0:0:0-0"));
    }
}

public class RpmVersionComparerTests
{
    private static readonly RpmVersionComparer C = RpmVersionComparer.Instance;

    /// <summary>Todos os vetores de tests/rpmvercmp.at do rpm (a|b|esperado).</summary>
    public static TheoryData<string, string, int> OfficialVectors()
    {
        var data = new TheoryData<string, string, int>();
        foreach (var line in File.ReadLines(Path.Combine(AppContext.BaseDirectory, "Data", "rpm-vercmp.data")))
        {
            var p = line.Split('|');
            data.Add(p[0], p[1], int.Parse(p[2]));
        }
        return data;
    }

    [Theory, MemberData(nameof(OfficialVectors))]
    public void RpmVerCmp_Oficial(string a, string b, int expected)
    {
        Assert.Equal(expected, RpmVersionComparer.VerCmp(a, b));
    }

    public static TheoryData<string, string, int> EvrVectors => new()
    {
        { "0:1.2-3.el9", "1.2-3.el9", 0 },
        { "1:1.0-1", "0:9.9-9", 1 },
        { "1.13.1-3.el9_3.3.alma.1", "1.13.1-3.el9_3.3.alma.1", 0 },
        { "1.13.1-3.el9_3.2.alma.1", "1.13.1-3.el9_3.3.alma.1", -1 },
        { "1.13.1-3.el9_3.3.alma.1", "1.13.1-3.el9_4.1", -1 },
        { "115.6.0-1.el8_9", "0:115.6.0-1.el8_9", 0 },
        { "115.5.0-1.el8_9", "0:115.6.0-1.el8_9", -1 },
        { "1.0-1.el9_4", "1.0-1.el9_4.1", -1 },
        { "1.0-1.el9", "1.0-1.el9_4", -1 },
        { "2.34-100.el9", "2.34-60.el9_4.1", 1 },
        { "1.0~rc1-1.el9", "1.0-1.el9", -1 },
        { "3.0.7-27.el9", "3.0.7-27.el9_0.3", -1 },
        { "3.0.7-28.el9_4", "3.0.7-27.el9_4", 1 },
        { "1.0^git1-1", "1.0-1", 1 },
        { "9.0.1-2.el9.rocky.0.1", "9.0.1-2.el9.rocky.0.2", -1 },
        { "10-1", "9-1", 1 },
        { "1.0", "1.0-5", 0 },
    };

    [Theory, MemberData(nameof(EvrVectors))]
    public void Evr(string a, string b, int expected)
    {
        Assert.Equal(expected, Math.Sign(C.Compare(a, b)));
        Assert.Equal(-expected, Math.Sign(C.Compare(b, a)));
    }
}

public class ApkVersionComparerTests
{
    private static readonly ApkVersionComparer C = ApkVersionComparer.Instance;

    /// <summary>Todos os vetores de apk-tools/test/version.data ("a op b").</summary>
    public static TheoryData<string, string, int> OfficialVectors()
    {
        var data = new TheoryData<string, string, int>();
        foreach (var raw in File.ReadLines(Path.Combine(AppContext.BaseDirectory, "Data", "apk-version.data")))
        {
            var line = raw.Split('#')[0].Trim();
            if (line.Length == 0) continue;
            var t = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            data.Add(t[0], t[2], t[1] switch { "<" => -1, ">" => 1, _ => 0 });
        }
        return data;
    }

    [Theory, MemberData(nameof(OfficialVectors))]
    public void Oficial(string a, string b, int expected)
    {
        Assert.Equal(expected, Math.Sign(C.Compare(a, b)));
    }

    public static TheoryData<string, string, int> ExtraVectors => new()
    {
        { "3.8.3-r0", "3.8.2-r5", 1 },
        { "3.8.3-r0", "3.8.3-r0", 0 },
        { "1.2.3_rc1-r0", "1.2.3-r0", -1 },
        { "1.2.3_alpha", "1.2.3_beta", -1 },
        { "1.2.3_beta", "1.2.3_pre", -1 },
        { "1.2.3_pre", "1.2.3_rc", -1 },
        { "1.2.3_p1", "1.2.3", 1 },
        { "1.2.3_git20240101", "1.2.3", 1 },
        { "1.2.3a", "1.2.3", 1 },
        { "1.2.3a", "1.2.3b", -1 },
        { "1.2.3-r10", "1.2.3-r9", 1 },
        { "1.2.3-r0", "1.2.3", 1 },
        { "3.0.13-r0", "3.0.9-r4", 1 },
        { "1.1.1w-r0", "1.1.1v-r5", 1 },
        { "2.7.10-r3", "2.7.10-r10", -1 },
    };

    [Theory, MemberData(nameof(ExtraVectors))]
    public void Extras(string a, string b, int expected)
    {
        Assert.Equal(expected, Math.Sign(C.Compare(a, b)));
        Assert.Equal(-expected, Math.Sign(C.Compare(b, a)));
    }
}
