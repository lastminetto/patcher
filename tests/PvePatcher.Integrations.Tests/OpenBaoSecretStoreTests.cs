using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PvePatcher.Core;
using PvePatcher.Integrations.OpenBao;
using PvePatcher.Integrations.Proxmox;

namespace PvePatcher.Integrations.Tests;

public sealed class OpenBaoSecretStoreTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("bao-test").FullName;
    private readonly FakeClock _clock = new(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
    private readonly OpenBaoOptions _opt;
    private int _logins, _renews;
    private int _loginCode = 200;
    private int _renewCode = 200;
    private string _currentToken = "tok1";
    private string? _rejectToken;

    public OpenBaoSecretStoreTests()
    {
        File.WriteAllText(Path.Combine(_dir, "role_id"), "role-1\n");
        File.WriteAllText(Path.Combine(_dir, "secret_id"), "secret-1\n");
        _opt = new OpenBaoOptions
        {
            Address = "http://bao:8200",
            RoleIdFile = Path.Combine(_dir, "role_id"),
            SecretIdFile = Path.Combine(_dir, "secret_id"),
        };
    }

    public void Dispose() => Directory.Delete(_dir, true);

    private (OpenBaoSecretStore Store, FakeHandler Handler) Make(Func<Seen, HttpResponseMessage>? kv = null, bool sealedVault = false)
    {
        var handler = new FakeHandler(s =>
        {
            switch (s.Uri.AbsolutePath)
            {
                case "/v1/sys/seal-status":
                    return FakeHandler.Json($$"""{"initialized":true,"sealed":{{(sealedVault ? "true" : "false")}}}""");
                case "/v1/auth/approle/login":
                    _logins++;
                    _currentToken = $"tok{_logins}";
                    return _loginCode != 200
                        ? FakeHandler.Json("""{"errors":["invalid secret id"]}""", (HttpStatusCode)_loginCode)
                        : FakeHandler.Json($$$"""{"auth":{"client_token":"{{{_currentToken}}}","lease_duration":3600,"renewable":true}}""");
                case "/v1/auth/token/renew-self":
                    _renews++;
                    return _renewCode != 200
                        ? FakeHandler.Json("""{"errors":["permission denied"]}""", (HttpStatusCode)_renewCode)
                        : FakeHandler.Json("""{"auth":{"lease_duration":3600,"renewable":true}}""");
            }
            if (s.Headers.GetValueOrDefault("X-Vault-Token") == _rejectToken)
                return FakeHandler.Json("""{"errors":["permission denied"]}""", HttpStatusCode.Forbidden);
            return kv?.Invoke(s) ?? FakeHandler.Json("{}", HttpStatusCode.NotFound);
        });
        return (new OpenBaoSecretStore(new HttpClient(handler), _opt, _clock), handler);
    }

    private const string Kv = """{"data":{"data":{"token_id":"u@pve!svc","token_secret":"abc","n":5},"metadata":{"version":2}}}""";

    [Fact]
    public async Task Status_ReadyAfterLogin()
    {
        var (store, _) = Make();
        var st = await store.GetStatusAsync(default);
        Assert.Equal(VaultState.Ready, st.State);
        Assert.Equal(1, _logins);
    }

    [Fact]
    public async Task Status_Sealed()
    {
        var (store, _) = Make(sealedVault: true);
        Assert.Equal(VaultState.Sealed, (await store.GetStatusAsync(default)).State);
        Assert.Equal(0, _logins);
    }

    [Fact]
    public async Task Status_Unreachable()
    {
        var store = new OpenBaoSecretStore(new HttpClient(new FakeHandler(_ => throw new HttpRequestException("recusado"))), _opt, _clock);
        Assert.Equal(VaultState.Unreachable, (await store.GetStatusAsync(default)).State);
    }

    [Fact]
    public async Task Status_AuthFailed_AndReadThrows()
    {
        _loginCode = 400;
        var (store, _) = Make();

        Assert.Equal(VaultState.AuthFailed, (await store.GetStatusAsync(default)).State);
        var ex = await Assert.ThrowsAsync<VaultUnavailableException>(() => store.ReadAsync("a", default));
        Assert.Equal(VaultState.AuthFailed, ex.Status.State);
    }

    [Fact]
    public async Task Status_AuthFailedWhenCredentialFilesMissing()
    {
        File.Delete(_opt.SecretIdFile);
        var (store, _) = Make();
        Assert.Equal(VaultState.AuthFailed, (await store.GetStatusAsync(default)).State);
    }

    [Fact]
    public async Task Read_ReturnsDataAndSendsToken_AndCaches()
    {
        var (store, handler) = Make(_ => FakeHandler.Json(Kv));

        var d1 = await store.ReadAsync(SecretPaths.Cluster("c1"), default);
        var d2 = await store.ReadAsync(SecretPaths.Cluster("c1"), default);

        Assert.Equal("abc", d1!["token_secret"]);
        Assert.Equal("5", d1["n"]);
        Assert.Same(d1, d2);
        var get = handler.Requests.Single(r => r.Uri.AbsolutePath.StartsWith("/v1/pve-patcher/data"));
        Assert.Equal("/v1/pve-patcher/data/pve/clusters/c1", get.Uri.AbsolutePath);
        Assert.Equal("tok1", get.Headers["X-Vault-Token"]);
        Assert.Equal(1, handler.Requests.Count(r => r.Uri.AbsolutePath.Contains("/data/")));
    }

    [Fact]
    public async Task Read_CacheExpires()
    {
        var (store, handler) = Make(_ => FakeHandler.Json(Kv));
        await store.ReadAsync("x", default);
        _clock.Advance(TimeSpan.FromSeconds(61));
        await store.ReadAsync("x", default);
        Assert.Equal(2, handler.Requests.Count(r => r.Uri.AbsolutePath.Contains("/data/")));
    }

    [Fact]
    public async Task Read_MissingPathIsNull()
    {
        var (store, _) = Make();
        Assert.Null(await store.ReadAsync("nao/existe", default));
    }

    [Fact]
    public async Task Write_PostsDataEnvelope_AndInvalidatesCache()
    {
        var (store, handler) = Make(_ => FakeHandler.Json(Kv));
        await store.ReadAsync("p", default);

        await store.WriteAsync("p", new Dictionary<string, string> { ["k"] = "v" }, default);
        await store.ReadAsync("p", default);

        var post = handler.Requests.Single(r => r.Method == HttpMethod.Post && r.Uri.AbsolutePath.Contains("/data/"));
        Assert.Equal("""{"data":{"k":"v"}}""", post.Body);
        Assert.Equal(2, handler.Requests.Count(r => r.Method == HttpMethod.Get && r.Uri.AbsolutePath.Contains("/data/")));
    }

    [Fact]
    public async Task Delete_UsesMetadataEndpoint()
    {
        var (store, handler) = Make(_ => new HttpResponseMessage(HttpStatusCode.NoContent));
        await store.DeleteAsync("ssh/default", default);
        var del = handler.Requests.Single(r => r.Method == HttpMethod.Delete);
        Assert.Equal("/v1/pve-patcher/metadata/ssh/default", del.Uri.AbsolutePath);
    }

    [Fact]
    public async Task Forbidden_TriggersRelogin_AndRetries()
    {
        _rejectToken = "tok1";
        var (store, handler) = Make(_ => FakeHandler.Json(Kv));

        var data = await store.ReadAsync("p", default);

        Assert.NotNull(data);
        Assert.Equal(2, _logins);
        var gets = handler.Requests.Where(r => r.Uri.AbsolutePath.Contains("/data/")).ToList();
        Assert.Equal(["tok1", "tok2"], gets.Select(g => g.Headers["X-Vault-Token"]));
    }

    [Fact]
    public async Task Token_RenewedBeforeTtl_ThenReloginIfRenewFails()
    {
        var (store, _) = Make(_ => FakeHandler.Json(Kv));
        await store.ReadAsync("a", default);
        Assert.Equal(1, _logins);

        _clock.Advance(TimeSpan.FromMinutes(30)); // < 2/3 de 1h
        await store.ReadAsync("b", default);
        Assert.Equal(0, _renews);

        _clock.Advance(TimeSpan.FromMinutes(15)); // passou de 40 min
        await store.ReadAsync("c", default);
        Assert.Equal(1, _renews);
        Assert.Equal(1, _logins);

        _renewCode = 403;
        _clock.Advance(TimeSpan.FromMinutes(45));
        await store.ReadAsync("d", default);
        Assert.Equal(2, _renews);
        Assert.Equal(2, _logins);
    }

    [Fact]
    public async Task SealedDuringRead_ThrowsVaultUnavailable()
    {
        var (store, _) = Make(_ => FakeHandler.Json("""{"errors":["Vault is sealed"]}""", HttpStatusCode.ServiceUnavailable));
        var ex = await Assert.ThrowsAsync<VaultUnavailableException>(() => store.ReadAsync("p", default));
        Assert.Equal(VaultState.Sealed, ex.Status.State);
    }

    [Fact]
    public async Task ConcurrentReads_LoginOnce()
    {
        var (store, _) = Make(_ => FakeHandler.Json(Kv));
        await Task.WhenAll(Enumerable.Range(0, 20).Select(i => store.ReadAsync($"p{i}", default)));
        Assert.Equal(1, _logins);
    }

    [Fact]
    public void AddPvePatcherIntegrations_RegistersServicesAndBindsConfig()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["OpenBao:KvMount"] = "outro" })
            .Build();
        var sp = new ServiceCollection().AddPvePatcherIntegrations(config).BuildServiceProvider();

        Assert.IsType<OpenBaoSecretStore>(sp.GetRequiredService<ISecretStore>());
        Assert.IsType<ProxmoxClient>(sp.GetRequiredService<IProxmoxClient>());
        Assert.IsType<ProxmoxAuth>(sp.GetRequiredService<IProxmoxAuth>());
        Assert.IsType<IpSelector>(sp.GetRequiredService<IIpSelector>());
        var opts = sp.GetRequiredService<OpenBaoOptions>();
        Assert.Equal("outro", opts.KvMount);
        Assert.Equal("http://127.0.0.1:8200", opts.Address);
    }
}
