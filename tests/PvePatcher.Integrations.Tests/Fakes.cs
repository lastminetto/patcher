using System.Net;
using System.Text;
using PvePatcher.Core;

namespace PvePatcher.Integrations.Tests;

public sealed record Seen(HttpMethod Method, Uri Uri, string Body, IReadOnlyDictionary<string, string> Headers);

/// <summary>HttpMessageHandler programável; registra o que recebeu.</summary>
public sealed class FakeHandler(Func<Seen, HttpResponseMessage> respond) : HttpMessageHandler
{
    public List<Seen> Requests { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
        var headers = request.Headers.ToDictionary(h => h.Key, h => string.Join(",", h.Value), StringComparer.OrdinalIgnoreCase);
        var seen = new Seen(request.Method, request.RequestUri!, body, headers);
        lock (Requests) Requests.Add(seen);
        return respond(seen);
    }

    public static HttpResponseMessage Json(string json, HttpStatusCode code = HttpStatusCode.OK) =>
        new(code) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    public static HttpResponseMessage Data(string dataJson) => Json($"{{\"data\":{dataJson}}}");
}

public sealed class FakeSecrets(Dictionary<string, string>? token = null) : ISecretStore
{
    private readonly Dictionary<string, string> _token = token ?? new()
    {
        [SecretPaths.TokenId] = "pve-patcher@pve!svc",
        [SecretPaths.TokenSecret] = "s3cr3t",
    };

    public Task<VaultStatus> GetStatusAsync(CancellationToken ct) => Task.FromResult(new VaultStatus(VaultState.Ready, null));
    public Task<IReadOnlyDictionary<string, string>?> ReadAsync(string path, CancellationToken ct) =>
        Task.FromResult<IReadOnlyDictionary<string, string>?>(_token);
    public Task WriteAsync(string path, IReadOnlyDictionary<string, string> data, CancellationToken ct) => Task.CompletedTask;
    public Task DeleteAsync(string path, CancellationToken ct) => Task.CompletedTask;
}

public sealed class FakeClock(DateTimeOffset start) : TimeProvider
{
    private DateTimeOffset _now = start;
    public override DateTimeOffset GetUtcNow() => _now;
    public void Advance(TimeSpan span) => _now += span;
}
