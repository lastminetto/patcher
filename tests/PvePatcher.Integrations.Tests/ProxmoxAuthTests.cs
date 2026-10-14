using System.Net;
using PvePatcher.Core;
using PvePatcher.Integrations.Proxmox;

namespace PvePatcher.Integrations.Tests;

public class ProxmoxAuthTests
{
    private static readonly ClusterConfig Cluster = new("c1", "C1", ["https://a:8006"], null);

    private static (ProxmoxAuth Auth, FakeHandler Handler) Make(Func<Seen, HttpResponseMessage> respond)
    {
        var handler = new FakeHandler(respond);
        return (new ProxmoxAuth(new PveHttp(_ => handler)), handler);
    }

    [Fact]
    public async Task Login_Success()
    {
        var (auth, handler) = Make(_ => FakeHandler.Data("""{"ticket":"PVE:u@pve:ABC","CSRFPreventionToken":"csrf","username":"u@pve"}"""));

        var r = await auth.LoginAsync(Cluster, "u@pve", "p&ss", default);

        Assert.Equal(PveLoginStatus.Success, r.Status);
        Assert.Equal("PVE:u@pve:ABC", r.Ticket);
        Assert.Equal("csrf", r.CsrfToken);
        Assert.Equal("u@pve", r.UserId);
        Assert.Contains("password=p%26ss", handler.Requests[0].Body);
        Assert.False(handler.Requests[0].Headers.ContainsKey("Authorization")); // não usa o token de serviço
    }

    [Fact]
    public async Task Login_WrongPassword_IsFailedNotException()
    {
        var (auth, _) = Make(_ => FakeHandler.Json("""{"data":null}""", HttpStatusCode.Unauthorized));

        var r = await auth.LoginAsync(Cluster, "u@pve", "x", default);

        Assert.Equal(PveLoginStatus.Failed, r.Status);
        Assert.Contains("inválidos", r.Error);
    }

    [Fact]
    public async Task Login_WithTfa_ThenTotp()
    {
        var (auth, handler) = Make(s => s.Body.Contains("tfa-challenge")
            ? FakeHandler.Data("""{"ticket":"PVE:u@pve:FULL","CSRFPreventionToken":"c2","username":"u@pve"}""")
            : FakeHandler.Data("""{"ticket":"PVE:u@pve:!tfa!{...}","NeedTFA":1,"username":"u@pve"}"""));

        var first = await auth.LoginAsync(Cluster, "u@pve", "pw", default);
        Assert.Equal(PveLoginStatus.NeedTotp, first.Status);
        Assert.Null(first.CsrfToken);

        var second = await auth.CompleteTotpAsync(Cluster, "u@pve", first.Ticket!, " 123456 ", default);
        Assert.Equal(PveLoginStatus.Success, second.Status);
        Assert.Equal("PVE:u@pve:FULL", second.Ticket);

        var body = handler.Requests[1].Body;
        Assert.Contains("password=totp%3A123456", body);
        Assert.Contains("tfa-challenge=", body);
    }

    [Fact]
    public async Task Totp_WrongCode_IsFailed()
    {
        var (auth, _) = Make(_ => FakeHandler.Json("{}", HttpStatusCode.Unauthorized));
        var r = await auth.CompleteTotpAsync(Cluster, "u@pve", "t", "000000", default);
        Assert.Equal(PveLoginStatus.Failed, r.Status);
    }

    [Fact]
    public async Task Permissions_ParsedAndSentWithCookie()
    {
        var (auth, handler) = Make(_ => FakeHandler.Data("""
            {"/":{"Sys.Audit":1,"VM.Audit":1},"/vms/100":{"VM.Snapshot":0}}
            """));

        var perms = await auth.GetPermissionsAsync(Cluster, "PVE:u@pve:ABC", default);

        Assert.Equal(2, perms.Count);
        Assert.Contains("Sys.Audit", perms["/"]);
        Assert.Contains("VM.Snapshot", perms["/vms/100"]);
        Assert.Equal("PVEAuthCookie=PVE:u@pve:ABC", handler.Requests[0].Headers["Cookie"]);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("[]")]
    [InlineData("null")]
    public async Task Permissions_UserWithoutPrivilegesIsEmpty(string data)
    {
        var (auth, _) = Make(_ => FakeHandler.Data(data));
        Assert.Empty(await auth.GetPermissionsAsync(Cluster, "t", default));
    }
}
