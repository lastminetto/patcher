namespace PvePatcher.Vuln.Versioning;

/// <summary>
/// Port fiel de apk_version_compare (apk-tools, src/version.c):
/// {digit}{.digit}...{letter}{_suf{#}}...{-r#}.
/// </summary>
public sealed class ApkVersionComparer : IVersionComparer
{
    public static readonly ApkVersionComparer Instance = new();

    private const int Invalid = -1, DigitOrZero = 0, Digit = 1, Letter = 2, Suffix = 3, SuffixNo = 4, RevisionNo = 5, End = 6;
    private static readonly string[] PreSuffixes = ["alpha", "beta", "pre", "rc"];
    private static readonly string[] PostSuffixes = ["cvs", "svn", "git", "hg", "p"];

    public int Compare(string a, string b)
    {
        int at = Digit, bt = Digit, pa = 0, pb = 0;
        long av = 0, bv = 0;

        while (at == bt && at != End && at != Invalid && av == bv)
        {
            av = GetToken(ref at, a, ref pa);
            bv = GetToken(ref bt, b, ref pb);
        }

        if (av < bv) return -1;
        if (av > bv) return 1;
        if (at == bt) return 0;

        // prefixos iguais: o lado que não terminou é maior, exceto se o resto for sufixo de pré-lançamento
        var tt = at;
        if (at == Suffix && GetToken(ref tt, a, ref pa) < 0) return -1;
        tt = bt;
        if (bt == Suffix && GetToken(ref tt, b, ref pb) < 0) return 1;
        if (at > bt) return -1;
        if (bt > at) return 1;
        return 0;
    }

    private static bool IsLower(char c) => c is >= 'a' and <= 'z';

    private static void NextToken(ref int type, string s, ref int pos)
    {
        var n = Invalid;
        if (pos >= s.Length || s[pos] == '\0')
        {
            n = End;
        }
        else if ((type == Digit || type == DigitOrZero) && IsLower(s[pos]))
        {
            n = Letter;
        }
        else if (type == Letter && char.IsAsciiDigit(s[pos]))
        {
            n = Digit;
        }
        else if (type == Suffix && char.IsAsciiDigit(s[pos]))
        {
            n = SuffixNo;
        }
        else
        {
            switch (s[pos])
            {
                case '.': n = DigitOrZero; break;
                case '_': n = Suffix; break;
                case '-':
                    if (s.Length - pos > 1 && s[pos + 1] == 'r')
                    {
                        n = RevisionNo;
                        pos++;
                    }
                    else n = Invalid;
                    break;
            }
            pos++;
        }

        if (n < type &&
            !((n == DigitOrZero && type == Digit) ||
              (n == Suffix && type == SuffixNo) ||
              (n == Digit && type == Letter)))
            n = Invalid;
        type = n;
    }

    private static long GetToken(ref int type, string s, ref int pos)
    {
        var len = s.Length - pos;
        if (len <= 0)
        {
            type = End;
            return 0;
        }

        int i = 0, nt = Invalid;
        long v = 0;
        var invalid = false;

        switch (type)
        {
            case DigitOrZero when s[pos] == '0':
                while (i + 1 < len && s[pos + i + 1] == '0') i++;
                nt = Digit;
                v = -i;
                break;
            case DigitOrZero:
            case Digit:
            case SuffixNo:
            case RevisionNo:
                while (i < len && char.IsAsciiDigit(s[pos + i]))
                {
                    v = unchecked(v * 10 + (s[pos + i] - '0'));
                    i++;
                }
                if (i >= 18) invalid = true;
                break;
            case Letter:
                v = s[pos];
                i = 1;
                break;
            case Suffix:
                {
                    var found = false;
                    for (v = 0; v < PreSuffixes.Length; v++)
                    {
                        i = PreSuffixes[v].Length;
                        if (i <= len && string.CompareOrdinal(s, pos, PreSuffixes[v], 0, i) == 0) { found = true; break; }
                    }
                    if (found)
                    {
                        v -= PreSuffixes.Length;
                        break;
                    }
                    for (v = 0; v < PostSuffixes.Length; v++)
                    {
                        i = PostSuffixes[v].Length;
                        if (i <= len && string.CompareOrdinal(s, pos, PostSuffixes[v], 0, i) == 0) { found = true; break; }
                    }
                    if (!found) invalid = true;
                    break;
                }
            default:
                invalid = true;
                break;
        }

        if (invalid)
        {
            type = Invalid;
            return -1;
        }

        pos += i;
        if (pos >= s.Length) type = End;
        else if (nt != Invalid) type = nt;
        else NextToken(ref type, s, ref pos);
        return v;
    }
}
