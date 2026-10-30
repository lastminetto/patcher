using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using NSubstitute;
using PvePatcher.Core;
using PvePatcher.Web.Data;
using PvePatcher.Web.Jobs;
using PvePatcher.Web.Services;

namespace PvePatcher.Web.Tests;

public class TerminalProtocolTests
{
    [Theory]
    [InlineData("""{"t":"resize","c":120,"r":40}""", true, 120, 40)]
    [InlineData("""{"t":"resize","c":0,"r":40}""", false, 0, 0)]
    [InlineData("""{"t":"resize","c":120,"r":5000}""", false, 0, 0)]
    [InlineData("""{"t":"ping"}""", false, 0, 0)]
    [InlineData("""{"t":"resize","c":"120","r":40}""", false, 0, 0)]
    [InlineData("não é json", false, 0, 0)]
    [InlineData("[1,2]", false, 0, 0)]
    public void Resize(string json, bool ok, int cols, int rows)
    {
        Assert.Equal(ok, TerminalProtocol.TryParseResize(json, out var c, out var r));
        if (ok) { Assert.Equal(cols, c); Assert.Equal(rows, r); }
    }

    [Theory]
    [InlineData("prod/101", true, "prod", 101)]
    [InlineData("lab/x/7", true, "lab/x", 7)]
    [InlineData("prod/abc", false, null, 0)]
    [InlineData("101", false, null, 0)]
    [InlineData("prod/0", false, null, 0)]
    [InlineData(null, false, null, 0)]
    public void Vm(string? value, bool ok, string? cluster, int id)
    {
        Assert.Equal(ok, TerminalProtocol.TryParseVm(value, out var key));
        if (ok) Assert.Equal(new VmKey(cluster!, id), key);
    }

    [Theory]
    [InlineData("https://172.22.104.31:8443", "https", "172.22.104.31:8443", true)]
    [InlineData("https://PATCHER:8443", "https", "patcher:8443", true)]
    [InlineData("https://patcher.example", "https", "patcher.example", true)]
    [InlineData("https://evil.example", "https", "patcher.example", false)]
    [InlineData("http://patcher.example", "https", "patcher.example", false)]
    [InlineData("https://patcher.example:444", "https", "patcher.example", false)]
    [InlineData(null, "https", "patcher.example", false)]
    [InlineData("null", "https", "patcher.example", false)]
    public void Origin(string? origin, string scheme, string host, bool same) =>
        Assert.Equal(same, TerminalProtocol.IsSameOrigin(origin, scheme, host));
}

public class SftpPathsTests
{
    [Theory]
    [InlineData("/root", "a.txt", "/root/a.txt")]
    [InlineData("/", "etc", "/etc")]
    public void Combine(string dir, string name, string expected) => Assert.Equal(expected, SftpPaths.Combine(dir, name));

    [Theory]
    [InlineData("..")]
    [InlineData(".")]
    [InlineData("a/b")]
    [InlineData("")]
    [InlineData("   ")]
    public void Combine_rejeita_nomes_que_nao_sao_um_componente(string name) =>
        Assert.Throws<ArgumentException>(() => SftpPaths.Combine("/root", name));

    [Theory]
    [InlineData("/root/docs", "/root")]
    [InlineData("/root/", "/")]
    [InlineData("/root", "/")]
    [InlineData("/", "/")]
    public void Parent(string path, string expected) => Assert.Equal(expected, SftpPaths.Parent(path));

    [Theory]
    [InlineData(null, "/home/heber", "/home/heber")]
    [InlineData("docs", "/home/heber", "/home/heber/docs")]
    [InlineData("/etc/../var//log/./", "/root", "/var/log")]
    [InlineData("/../../", "/root", "/")]
    public void Normalize(string? path, string home, string expected) => Assert.Equal(expected, SftpPaths.Normalize(path, home));
}

public class ConsoleSessionRegistryTests
{
    private static ConsoleSessionRegistry Registry(int perUser, int total) =>
        new(Options.Create(new ConsoleOptions { MaxSessionsPerUser = perUser, MaxSessions = total }));

    [Fact]
    public void Limite_por_usuario_e_liberacao()
    {
        var r = Registry(2, 10);
        var a = r.TryAcquire("ana@pve", out _);
        var b = r.TryAcquire("ana@pve", out _);
        Assert.NotNull(a); Assert.NotNull(b);
        Assert.Null(r.TryAcquire("ana@pve", out var why));
        Assert.Contains("por usuário", why);
        Assert.NotNull(r.TryAcquire("bia@pve", out _));

        a!.Dispose();
        a.Dispose(); // idempotente
        Assert.Equal(2, r.Total);
        Assert.NotNull(r.TryAcquire("ana@pve", out _));
    }

    [Fact]
    public void Limite_total()
    {
        var r = Registry(5, 2);
        Assert.NotNull(r.TryAcquire("a", out _));
        Assert.NotNull(r.TryAcquire("b", out _));
        Assert.Null(r.TryAcquire("c", out var why));
        Assert.Contains("no servidor", why);
    }
}

/// <summary>Resolver contra um SQLite temporário real (StateStore/SettingsService são concretos).</summary>
public sealed class VmConnectionResolverTests : IDisposable
{
    private readonly string _db = Path.Combine(Path.GetTempPath(), $"pvp-test-{Guid.NewGuid():N}.db");
    private readonly ISecretStore _vault = Substitute.For<ISecretStore>();
    private readonly IIpSelector _ip = Substitute.For<IIpSelector>();
    private readonly StateStore _store;
    private readonly SettingsService _settings;
    private readonly VmConnectionResolver _resolver;
    private static readonly VmKey Key = new("prod", 101);

    private sealed class Factory(string path) : IDbContextFactory<AppDb>
    {
        public AppDb CreateDbContext() => new(new DbContextOptionsBuilder<AppDb>().UseSqlite($"Data Source={path};Pooling=False").Options);
    }

    public VmConnectionResolverTests()
    {
        var factory = new Factory(_db);
        using (var db = factory.CreateDbContext())
        {
            db.Database.EnsureCreated();
            db.Vms.Add(new VmEntity { ClusterId = "prod", VmId = 101, Name = "web", SshPort = 2222 });
            db.SaveChanges();
        }
        var events = new AppEvents();
        _store = new StateStore(factory, events);
        _settings = new SettingsService(factory, events);
        _ip.Select(Arg.Any<DiscoveredVm>(), Arg.Any<IpOverride?>(), Arg.Any<IReadOnlyList<IPNetwork>>()).Returns(IPAddress.Parse("10.0.0.5"));
        _resolver = new VmConnectionResolver(_store, _settings, _vault, new VmIpService(_ip, _settings));
    }

    public void Dispose()
    {
        try { File.Delete(_db); } catch { /* ignora */ }
    }

    private void Secret(string path, params (string K, string V)[] kv) =>
        _vault.ReadAsync(path, Arg.Any<CancellationToken>()).Returns(kv.ToDictionary(x => x.K, x => x.V));

    [Fact]
    public async Task Console_usa_chave_e_usuario_proprios_com_certificado()
    {
        Secret(SecretPaths.SshConsole, (SecretPaths.PrivateKey, "PRIV"), (SecretPaths.Certificate, "ssh-ed25519-cert-v01@openssh.com AAAA"));
        var s = _settings.Current;
        s.ConsoleUser = "heber";
        await _settings.SaveAsync(s);

        var t = await _resolver.ForConsoleAsync(Key, default);

        Assert.Equal(("10.0.0.5", 2222, "heber", "PRIV"), (t.Host, t.Port, t.User, t.PrivateKey));
        Assert.Equal("ssh-ed25519-cert-v01@openssh.com AAAA", t.Certificate);
        Assert.Null(t.KnownHostKeySha256);
        await _vault.DidNotReceive().ReadAsync(SecretPaths.SshDefault, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Console_sem_chave_explica_onde_configurar()
    {
        _vault.ReadAsync(SecretPaths.SshConsole, Arg.Any<CancellationToken>()).Returns((IReadOnlyDictionary<string, string>?)null);
        var ex = await Assert.ThrowsAsync<JobFailedException>(() => _resolver.ForConsoleAsync(Key, default));
        Assert.Contains("Terminal SSH", ex.Message);
    }

    [Fact]
    public async Task Primeira_conexao_grava_host_key_e_a_trocada_e_aceita_automaticamente()
    {
        Secret(SecretPaths.SshConsole, (SecretPaths.PrivateKey, "PRIV"));
        var t = await _resolver.ForConsoleAsync(Key, default);
        await _resolver.ConnectAsync(Key, t, _ => Task.FromResult("sess"), _ => "SHA256:aaa", null);
        Assert.Equal("SHA256:aaa", (await _store.GetVmAsync(Key))!.KnownHostKey);

        var t2 = await _resolver.ForConsoleAsync(Key, default);
        Assert.Equal("SHA256:aaa", t2.KnownHostKeySha256);
        var tried = new List<string?>();
        var logs = new List<string>();
        var sess = await _resolver.ConnectAsync(Key, t2, x =>
        {
            tried.Add(x.KnownHostKeySha256);
            return x.KnownHostKeySha256 == "SHA256:bbb" ? Task.FromResult("sess") : throw new HostKeyMismatchException("SHA256:aaa", "SHA256:bbb");
        }, _ => "SHA256:bbb", logs.Add);

        Assert.Equal("sess", sess);
        Assert.Equal(["SHA256:aaa", "SHA256:bbb"], tried);
        Assert.Contains(logs, l => l.Contains("aceita automaticamente"));
        var vm = (await _store.GetVmAsync(Key))!;
        Assert.Equal(("SHA256:bbb", (string?)null), (vm.KnownHostKey, vm.PendingHostKey));
        Assert.NotEqual(ScanState.HostKeyChanged, vm.State);
    }

    [Fact]
    public async Task VM_ja_bloqueada_por_host_key_e_destravada()
    {
        Secret(SecretPaths.SshConsole, (SecretPaths.PrivateKey, "PRIV"));
        await _store.UpdateVmAsync(Key, v =>
        {
            v.KnownHostKey = "SHA256:aaa"; v.PendingHostKey = "SHA256:bbb";
            v.State = ScanState.HostKeyChanged; v.LastError = "Host key mudou";
        });

        var t = await _resolver.ForConsoleAsync(Key, default);

        Assert.Equal("SHA256:bbb", t.KnownHostKeySha256);
        var vm = (await _store.GetVmAsync(Key))!;
        Assert.Equal((ScanState.None, (string?)null, (string?)null), (vm.State, vm.PendingHostKey, vm.LastError));
    }

    [Fact]
    public async Task Patcher_continua_usando_a_chave_padrao()
    {
        _vault.ReadAsync(SecretPaths.SshVm("prod", 101), Arg.Any<CancellationToken>()).Returns((IReadOnlyDictionary<string, string>?)null);
        Secret(SecretPaths.SshDefault, (SecretPaths.PrivateKey, "DEFAULT"));
        var t = await _resolver.ForPatcherAsync(Key, default);
        Assert.Equal(("patcher", "DEFAULT"), (t.User, t.PrivateKey));
        Assert.Null(t.Certificate);
    }
}

public sealed class ConsoleKeyTests : IDisposable
{
    private readonly string _db = Path.Combine(Path.GetTempPath(), $"pvp-test-{Guid.NewGuid():N}.db");
    private readonly ISecretStore _vault = Substitute.For<ISecretStore>();
    private readonly SecretsService _secrets;

    private sealed class Factory(string path) : IDbContextFactory<AppDb>
    {
        public AppDb CreateDbContext() => new(new DbContextOptionsBuilder<AppDb>().UseSqlite($"Data Source={path};Pooling=False").Options);
    }

    public ConsoleKeyTests()
    {
        var factory = new Factory(_db);
        using (var db = factory.CreateDbContext()) db.Database.EnsureCreated();
        _secrets = new SecretsService(_vault, new SettingsService(factory, new AppEvents()), TimeProvider.System);
    }

    public void Dispose()
    {
        try { File.Delete(_db); } catch { /* ignora */ }
    }

    [Fact]
    public async Task Chave_valida_vai_para_ssh_console_e_nao_toca_na_padrao()
    {
        var kp = Ed25519OpenSsh.Generate("t");
        await _secrets.SetConsoleKeyAsync(kp.PrivateKey, kp.PublicKey, null, null, default);
        await _vault.Received(1).WriteAsync(SecretPaths.SshConsole,
            Arg.Is<IReadOnlyDictionary<string, string>>(d => d[SecretPaths.PublicKey] == kp.PublicKey && !d.ContainsKey(SecretPaths.Certificate)),
            Arg.Any<CancellationToken>());
        await _vault.DidNotReceive().WriteAsync(SecretPaths.SshDefault, Arg.Any<IReadOnlyDictionary<string, string>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Chave_ou_certificado_invalidos_nao_sao_gravados()
    {
        var kp = Ed25519OpenSsh.Generate("t");
        var bad = await Assert.ThrowsAsync<ArgumentException>(() => _secrets.SetConsoleKeyAsync("lixo", null, null, null, default));
        Assert.Contains("Chave privada inválida", bad.Message);
        var badCert = await Assert.ThrowsAsync<ArgumentException>(() => _secrets.SetConsoleKeyAsync(kp.PrivateKey, null, null, "ssh-ed25519-cert-v01@openssh.com AAAA", default));
        Assert.Contains("certificado", badCert.Message);
        await _vault.DidNotReceive().WriteAsync(Arg.Any<string>(), Arg.Any<IReadOnlyDictionary<string, string>>(), Arg.Any<CancellationToken>());
    }
}
