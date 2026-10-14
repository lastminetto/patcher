using System.Net;
using PvePatcher.Core;
using PvePatcher.Integrations.Proxmox;

namespace PvePatcher.Integrations.Tests;

public class ProxmoxClientTests
{
    private static readonly ClusterConfig Cluster = new("c1", "Cluster 1", ["https://a:8006", "https://b:8006"], null);

    private const string Resources = """
        {"data":[
          {"type":"qemu","vmid":100,"node":"pve1","name":"web","status":"running","template":0},
          {"type":"qemu","vmid":101,"node":"pve2","name":"db","status":"stopped"},
          {"type":"qemu","vmid":102,"node":"pve1","name":"tpl","status":"stopped","template":1},
          {"type":"lxc","vmid":200,"node":"pve1","name":"ct","status":"running"},
          {"type":"qemu","vmid":103,"node":"pve2","name":"mudo","status":"running"},
          {"type":"storage","id":"storage/pve1/local","node":"pve1"}
        ]}
        """;

    private const string Ifaces = """
        {"data":{"result":[
          {"name":"lo","hardware-address":"00:00:00:00:00:00","ip-addresses":[{"ip-address":"127.0.0.1","ip-address-type":"ipv4","prefix":8}]},
          {"name":"eth0","hardware-address":"bc:24:11:aa:bb:cc","ip-addresses":[
            {"ip-address":"172.22.10.5","ip-address-type":"ipv4","prefix":24},
            {"ip-address":"2001:db8::5","ip-address-type":"ipv6","prefix":64},
            {"ip-address":"fe80::be24:11ff:feaa:bbcc","ip-address-type":"ipv6","prefix":64}]},
          {"name":"docker0","hardware-address":"02:42:ac:11:00:01","ip-addresses":[{"ip-address":"172.17.0.1","ip-address-type":"ipv4","prefix":16}]},
          {"name":"veth1234","hardware-address":"aa:aa:aa:aa:aa:aa"}
        ]}}
        """;

    private const string OsInfo = """
        {"data":{"result":{"id":"debian","version-id":"12","pretty-name":"Debian GNU/Linux 12 (bookworm)","name":"Debian GNU/Linux"}}}
        """;

    private static (ProxmoxClient Client, FakeHandler Handler) Make(Func<Seen, HttpResponseMessage> respond, ProxmoxClientOptions? opt = null)
    {
        var handler = new FakeHandler(respond);
        var client = new ProxmoxClient(new FakeSecrets(), new PveHttp(_ => handler),
            opt ?? new ProxmoxClientOptions { TaskPollInterval = TimeSpan.FromMilliseconds(1), PingInitialDelay = TimeSpan.FromMilliseconds(1) });
        return (client, handler);
    }

    private static HttpResponseMessage DiscoveryRouter(Seen s) => s.Uri.AbsolutePath switch
    {
        "/api2/json/cluster/resources" => FakeHandler.Json(Resources),
        "/api2/json/nodes/pve1/qemu/100/agent/network-get-interfaces" => FakeHandler.Json(Ifaces),
        "/api2/json/nodes/pve1/qemu/100/agent/get-osinfo" => FakeHandler.Json(OsInfo),
        _ => FakeHandler.Json("""{"data":null,"message":"QEMU guest agent is not running"}""", HttpStatusCode.InternalServerError),
    };

    [Fact]
    public async Task Discover_FiltersTemplatesAndMapsAgentData()
    {
        var (client, handler) = Make(DiscoveryRouter);

        var vms = await client.DiscoverVmsAsync(Cluster, default);

        Assert.Equal([100, 101, 103], vms.Select(v => v.VmId));
        var web = vms[0];
        Assert.True(web.AgentResponding);
        Assert.Equal(["eth0", "docker0", "veth1234"], web.Nics.Select(n => n.Name)); // lo descartado
        Assert.Equal("bc:24:11:aa:bb:cc", web.Nics[0].Mac);
        Assert.Contains(IPAddress.Parse("2001:db8::5"), web.Nics[0].Addresses);
        Assert.Empty(web.Nics[2].Addresses);
        Assert.Equal(Distro.Debian, web.Os!.Distro);
        Assert.Equal("12", web.Os.VersionId);
        Assert.Null(web.Os.Codename);

        Assert.False(vms[1].AgentResponding); // parada: nem consulta o agent
        Assert.Empty(vms[1].Nics);
        Assert.False(vms[2].AgentResponding); // agent mudo não derruba o discovery
        Assert.Null(vms[2].Os);
        Assert.DoesNotContain(handler.Requests, r => r.Uri.AbsolutePath.Contains("/qemu/101/"));
        Assert.All(handler.Requests, r => Assert.Equal("PVEAPIToken=pve-patcher@pve!svc=s3cr3t", r.Headers["Authorization"]));
    }

    [Fact]
    public async Task Failover_NextEndpointOnConnectionError()
    {
        var (client, handler) = Make(s => s.Uri.Host == "a"
            ? throw new HttpRequestException("recusado")
            : DiscoveryRouter(s));

        var node = await client.LocateVmAsync(Cluster, 101, default);

        Assert.Equal("pve2", node);
        Assert.Equal(["a", "b"], handler.Requests.Select(r => r.Uri.Host));
    }

    [Fact]
    public async Task Failover_NotOnHttp4xx()
    {
        var (client, handler) = Make(_ => FakeHandler.Json("""{"data":null,"message":"permission check failed"}""", HttpStatusCode.Forbidden));

        var ex = await Assert.ThrowsAsync<ProxmoxHttpException>(() => client.LocateVmAsync(Cluster, 1, default));

        Assert.Equal(403, ex.StatusCode);
        Assert.Contains("permission check failed", ex.Message);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task AllEndpointsDown_ThrowsProxmoxException()
    {
        var (client, _) = Make(_ => throw new HttpRequestException("sem rota"));
        await Assert.ThrowsAsync<ProxmoxException>(() => client.LocateVmAsync(Cluster, 1, default));
    }

    [Fact]
    public async Task Locate_ReturnsNullWhenMissing()
    {
        var (client, _) = Make(DiscoveryRouter);
        Assert.Null(await client.LocateVmAsync(Cluster, 999, default));
    }

    [Fact]
    public async Task ListSnapshots_IgnoresCurrent()
    {
        var (client, _) = Make(_ => FakeHandler.Data("""
            [{"name":"antes_patch","description":"x","snaptime":1760000000,"parent":"a"},{"name":"current","digest":"d"}]
            """));

        var snaps = await client.ListSnapshotsAsync(Cluster, new VmRef("c1", "pve1", 100), default);

        var s = Assert.Single(snaps);
        Assert.Equal("antes_patch", s.Name);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1760000000), s.Created);
    }

    private const string Upid = "UPID:pve1:00001234:00ABCDEF:67000000:qmsnapshot:100:pve-patcher@pve!svc:";

    [Fact]
    public async Task CreateSnapshot_PollsTaskUntilOk()
    {
        var polls = 0;
        var (client, handler) = Make(s =>
        {
            if (s.Method == HttpMethod.Post) return FakeHandler.Data($"\"{Upid}\"");
            return FakeHandler.Data(++polls < 3 ? """{"status":"running"}""" : """{"status":"stopped","exitstatus":"OK"}""");
        });

        await client.CreateSnapshotAsync(Cluster, new VmRef("c1", "pve1", 100), "antes_patch", "desc", default);

        var post = handler.Requests[0];
        Assert.Equal("/api2/json/nodes/pve1/qemu/100/snapshot", post.Uri.AbsolutePath);
        Assert.Contains("snapname=antes_patch", post.Body);
        Assert.Contains("vmstate=0", post.Body);
        Assert.Equal(3, polls);
        Assert.Contains(Upid, Uri.UnescapeDataString(handler.Requests[1].Uri.AbsolutePath));
    }

    [Fact]
    public async Task CreateSnapshot_TaskErrorIncludesLastLogLine()
    {
        var (client, _) = Make(s =>
        {
            if (s.Method == HttpMethod.Post) return FakeHandler.Data($"\"{Upid}\"");
            if (s.Uri.AbsolutePath.EndsWith("/log"))
                return FakeHandler.Data("""[{"n":1,"t":"snapshotting"},{"n":2,"t":"snapshot feature is not available"},{"n":3,"t":""}]""");
            return FakeHandler.Data("""{"status":"stopped","exitstatus":"snapshot feature is not available"}""");
        });

        var ex = await Assert.ThrowsAsync<ProxmoxException>(() =>
            client.CreateSnapshotAsync(Cluster, new VmRef("c1", "pve1", 100), "antes_patch", "d", default));

        Assert.Contains("snapshot feature is not available", ex.Message);
    }

    [Fact]
    public async Task DeleteSnapshot_UsesDeleteAndWaits()
    {
        var (client, handler) = Make(s => s.Method == HttpMethod.Delete
            ? FakeHandler.Data($"\"{Upid}\"")
            : FakeHandler.Data("""{"status":"stopped","exitstatus":"OK"}"""));

        await client.DeleteSnapshotAsync(Cluster, new VmRef("c1", "pve1", 100), "antes_patch", default);

        Assert.Equal("/api2/json/nodes/pve1/qemu/100/snapshot/antes_patch", handler.Requests[0].Uri.AbsolutePath);
    }

    [Theory]
    [InlineData("a", false)]
    [InlineData("1abc", false)]
    [InlineData("ab", true)]
    [InlineData("pre-patch_2026", true)]
    [InlineData("com espaco", false)]
    [InlineData("com.ponto", false)]
    public void SnapshotName_Validation(string name, bool valid) => Assert.Equal(valid, ProxmoxClient.IsValidSnapshotName(name));

    [Fact]
    public async Task CreateSnapshot_InvalidNameThrowsBeforeAnyRequest()
    {
        var (client, handler) = Make(DiscoveryRouter);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.CreateSnapshotAsync(Cluster, new VmRef("c1", "pve1", 100), "1ruim", "d", default));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task WaitForGuestAgent_RetriesUntilPingWorks()
    {
        var pings = 0;
        var (client, _) = Make(_ => ++pings < 3
            ? FakeHandler.Json("""{"data":null}""", HttpStatusCode.InternalServerError)
            : FakeHandler.Data("{}"));

        Assert.True(await client.WaitForGuestAgentAsync(Cluster, new VmRef("c1", "pve1", 100), TimeSpan.FromSeconds(5), default));
        Assert.Equal(3, pings);
    }

    [Fact]
    public async Task WaitForGuestAgent_TimesOut()
    {
        var (client, _) = Make(_ => FakeHandler.Json("""{"data":null}""", HttpStatusCode.InternalServerError));
        Assert.False(await client.WaitForGuestAgentAsync(Cluster, new VmRef("c1", "pve1", 100), TimeSpan.FromMilliseconds(30), default));
    }

    [Theory]
    [InlineData("AA:BB", "aabb", false)] // tamanho != 64
    public void Fingerprint_RequiresFullSha256(string expected, string _, bool ok)
        => Assert.Equal(ok, CertFingerprint.Matches(expected, new byte[] { 0xAA, 0xBB }));

    [Fact]
    public void Fingerprint_AcceptsColonsCaseAndPlainHex()
    {
        var hash = Enumerable.Range(0, 32).Select(i => (byte)(i * 7)).ToArray();
        var hex = Convert.ToHexString(hash);
        var colons = string.Join(":", Enumerable.Range(0, 32).Select(i => hex.Substring(i * 2, 2)));

        Assert.True(CertFingerprint.Matches(colons, hash));
        Assert.True(CertFingerprint.Matches(colons.ToLowerInvariant(), hash));
        Assert.True(CertFingerprint.Matches(hex.ToLowerInvariant(), hash));
        Assert.False(CertFingerprint.Matches(hex, hash.Reverse().ToArray()));
        Assert.False(CertFingerprint.Matches("", hash));
        Assert.True(CertFingerprint.Matches(new string('0', 64) + ", " + colons, hash)); // lista de nós
    }
}
