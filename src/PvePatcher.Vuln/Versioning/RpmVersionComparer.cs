namespace PvePatcher.Vuln.Versioning;

/// <summary>Port do rpmvercmp (rpm 4.15+, com ~ e ^) e comparação de EVR [epoch:]version[-release].</summary>
public sealed class RpmVersionComparer : IVersionComparer
{
    public static readonly RpmVersionComparer Instance = new();

    public int Compare(string a, string b)
    {
        var (ea, va, ra) = ParseEvr(a);
        var (eb, vb, rb) = ParseEvr(b);
        if (ea != eb) return ea < eb ? -1 : 1;
        var r = VerCmp(va, vb);
        if (r != 0) return r;
        // release ausente em um dos lados (rótulo parcial): não participa da comparação
        if (ra.Length == 0 || rb.Length == 0) return 0;
        return VerCmp(ra, rb);
    }

    internal static (long Epoch, string Version, string Release) ParseEvr(string s)
    {
        s = s.Trim();
        long epoch = 0;
        var colon = s.IndexOf(':');
        if (colon > 0 && long.TryParse(s.AsSpan(0, colon), out var e))
        {
            epoch = e;
            s = s[(colon + 1)..];
        }
        var hyphen = s.LastIndexOf('-');
        return hyphen < 0 ? (epoch, s, "") : (epoch, s[..hyphen], s[(hyphen + 1)..]);
    }

    private static char At(string s, int k) => k < s.Length ? s[k] : '\0';

    public static int VerCmp(string a, string b)
    {
        if (a == b) return 0;
        int one = 0, two = 0;

        while (one < a.Length || two < b.Length)
        {
            while (one < a.Length && !char.IsAsciiLetterOrDigit(a[one]) && a[one] != '~' && a[one] != '^') one++;
            while (two < b.Length && !char.IsAsciiLetterOrDigit(b[two]) && b[two] != '~' && b[two] != '^') two++;

            var c1 = At(a, one);
            var c2 = At(b, two);

            if (c1 == '~' || c2 == '~')
            {
                if (c1 != '~') return 1;
                if (c2 != '~') return -1;
                one++; two++;
                continue;
            }

            if (c1 == '^' || c2 == '^')
            {
                if (c1 == '\0') return -1;
                if (c2 == '\0') return 1;
                if (c1 != '^') return 1;
                if (c2 != '^') return -1;
                one++; two++;
                continue;
            }

            if (c1 == '\0' || c2 == '\0') break;

            int s1 = one, s2 = two;
            bool isNum;
            if (char.IsAsciiDigit(c1))
            {
                while (s1 < a.Length && char.IsAsciiDigit(a[s1])) s1++;
                while (s2 < b.Length && char.IsAsciiDigit(b[s2])) s2++;
                isNum = true;
            }
            else
            {
                while (s1 < a.Length && char.IsAsciiLetter(a[s1])) s1++;
                while (s2 < b.Length && char.IsAsciiLetter(b[s2])) s2++;
                isNum = false;
            }

            if (one == s1) return -1;
            if (two == s2) return isNum ? 1 : -1;

            var seg1 = a.AsSpan(one, s1 - one);
            var seg2 = b.AsSpan(two, s2 - two);
            if (isNum)
            {
                seg1 = seg1.TrimStart('0');
                seg2 = seg2.TrimStart('0');
                if (seg1.Length != seg2.Length) return seg1.Length > seg2.Length ? 1 : -1;
            }
            var cmp = seg1.SequenceCompareTo(seg2);
            if (cmp != 0) return cmp < 0 ? -1 : 1;

            one = s1; two = s2;
        }

        var left = one < a.Length;
        var right = two < b.Length;
        if (!left && !right) return 0;
        return left ? 1 : -1;
    }
}
