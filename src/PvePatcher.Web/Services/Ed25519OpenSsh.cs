using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;

namespace PvePatcher.Web.Services;

/// <summary>Geração de par ed25519 e serialização no formato OpenSSH (openssh-key-v1, sem passphrase).</summary>
public static class Ed25519OpenSsh
{
    public sealed record KeyPair(string PrivateKey, string PublicKey);

    public static KeyPair Generate(string comment)
    {
        var seed = RandomNumberGenerator.GetBytes(32);
        var pub = new Ed25519PrivateKeyParameters(seed, 0).GeneratePublicKey().GetEncoded();
        return Build(seed, pub, comment);
    }

    public static KeyPair Build(byte[] seed, byte[] pub, string comment)
    {
        var pubBlob = Concat(Str("ssh-ed25519"), Str(pub));

        var check = RandomNumberGenerator.GetBytes(4);
        var priv = new List<byte>();
        priv.AddRange(check); priv.AddRange(check);
        priv.AddRange(Str("ssh-ed25519"));
        priv.AddRange(Str(pub));
        priv.AddRange(Str([.. seed, .. pub]));
        priv.AddRange(Str(comment));
        for (byte i = 1; priv.Count % 8 != 0; i++) priv.Add(i);

        var body = Concat(
            Encoding.ASCII.GetBytes("openssh-key-v1\0"),
            Str("none"), Str("none"), Str(Array.Empty<byte>()),
            U32(1), Str(pubBlob), Str(priv.ToArray()));

        var b64 = Convert.ToBase64String(body);
        var sb = new StringBuilder("-----BEGIN OPENSSH PRIVATE KEY-----\n");
        for (var i = 0; i < b64.Length; i += 70) sb.Append(b64, i, Math.Min(70, b64.Length - i)).Append('\n');
        sb.Append("-----END OPENSSH PRIVATE KEY-----\n");

        var pubLine = $"ssh-ed25519 {Convert.ToBase64String(pubBlob)}" + (comment.Length > 0 ? " " + comment : "");
        return new KeyPair(sb.ToString(), pubLine);
    }

    private static byte[] U32(uint v) { var b = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, v); return b; }
    private static byte[] Str(string s) => Str(Encoding.UTF8.GetBytes(s));
    private static byte[] Str(byte[] d) => Concat(U32((uint)d.Length), d);
    private static byte[] Concat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();
}
