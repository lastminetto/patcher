namespace PvePatcher.Vuln.Versioning;

/// <summary>Port do verrevcmp / dpkg_version_compare: [epoch:]upstream[-revision].</summary>
public sealed class DpkgVersionComparer : IVersionComparer
{
    public static readonly DpkgVersionComparer Instance = new();

    public int Compare(string a, string b)
    {
        var (ea, ua, ra) = Parse(a);
        var (eb, ub, rb) = Parse(b);
        if (ea != eb) return ea < eb ? -1 : 1;
        var r = VerRevCmp(ua, ub);
        return r != 0 ? Math.Sign(r) : Math.Sign(VerRevCmp(ra, rb));
    }

    internal static (long Epoch, string Upstream, string Revision) Parse(string v)
    {
        v = v.Trim();
        long epoch = 0;
        var colon = v.IndexOf(':');
        if (colon > 0 && long.TryParse(v.AsSpan(0, colon), out var e))
        {
            epoch = e;
            v = v[(colon + 1)..];
        }
        var hyphen = v.LastIndexOf('-');
        return hyphen < 0 ? (epoch, v, "") : (epoch, v[..hyphen], v[(hyphen + 1)..]);
    }

    private static int Order(char c)
    {
        if (c == '\0' || char.IsAsciiDigit(c)) return 0;
        if (char.IsAsciiLetter(c)) return c;
        if (c == '~') return -1;
        return c + 256;
    }

    private static char At(string s, int k) => k < s.Length ? s[k] : '\0';

    private static int VerRevCmp(string a, string b)
    {
        int i = 0, j = 0;

        while (i < a.Length || j < b.Length)
        {
            var firstDiff = 0;
            while ((i < a.Length && !char.IsAsciiDigit(a[i])) || (j < b.Length && !char.IsAsciiDigit(b[j])))
            {
                var ac = Order(At(a, i));
                var bc = Order(At(b, j));
                if (ac != bc) return ac - bc;
                i++; j++;
            }
            while (At(a, i) == '0') i++;
            while (At(b, j) == '0') j++;
            while (char.IsAsciiDigit(At(a, i)) && char.IsAsciiDigit(At(b, j)))
            {
                if (firstDiff == 0) firstDiff = a[i] - b[j];
                i++; j++;
            }
            if (char.IsAsciiDigit(At(a, i))) return 1;
            if (char.IsAsciiDigit(At(b, j))) return -1;
            if (firstDiff != 0) return firstDiff;
        }
        return 0;
    }
}
