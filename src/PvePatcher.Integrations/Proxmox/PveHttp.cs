using System.Collections.Concurrent;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text.Json;
using PvePatcher.Core;

namespace PvePatcher.Integrations.Proxmox;

/// <summary>Erro HTTP devolvido pelo PVE (o servidor respondeu; não há failover).</summary>
public sealed class ProxmoxHttpException(int statusCode, string message) : ProxmoxException(message)
{
    public int StatusCode { get; } = statusCode;
}

/// <summary>Validação do certificado do pveproxy por impressão digital SHA-256.</summary>
public static class CertFingerprint
{
    public static string Normalize(string fingerprint) =>
        new(fingerprint.Where(Uri.IsHexDigit).Select(char.ToUpperInvariant).ToArray());

    /// <summary>
    /// <paramref name="expected"/> pode listar várias impressões separadas por vírgula, ponto e vírgula ou espaço
    /// (nós de um cluster costumam ter certificados próprios).
    /// </summary>
    public static bool Matches(string expected, ReadOnlySpan<byte> sha256)
    {
        var actual = Convert.ToHexString(sha256);
        foreach (var item in expected.Split([',', ';', ' ', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var normalized = Normalize(item);
            if (normalized.Length == 64 && string.Equals(normalized, actual, StringComparison.Ordinal))
                return true;
        }
        return false;
    }
}

/// <summary>HTTP para a API do PVE: um HttpClient por cluster, failover entre endpoints, desembrulha "data".</summary>
public sealed class PveHttp
{
    private static readonly JsonElement NullElement = JsonDocument.Parse("null").RootElement;

    private readonly Func<ClusterConfig, HttpMessageHandler> _handlerFactory;
    private readonly ConcurrentDictionary<string, HttpClient> _clients = new();

    public PveHttp(Func<ClusterConfig, HttpMessageHandler>? handlerFactory = null)
    {
        _handlerFactory = handlerFactory ?? CreateHandler;
    }

    public static HttpMessageHandler CreateHandler(ClusterConfig cluster)
    {
        var handler = new SocketsHttpHandler
        {
            ConnectTimeout = TimeSpan.FromSeconds(5),
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        };
        if (!string.IsNullOrWhiteSpace(cluster.CertFingerprintSha256))
        {
            var expected = cluster.CertFingerprintSha256;
            handler.SslOptions.RemoteCertificateValidationCallback = (_, cert, _, _) =>
                cert is not null && CertFingerprint.Matches(expected, cert.GetCertHash(HashAlgorithmName.SHA256));
        }
        return handler;
    }

    private HttpClient ClientFor(ClusterConfig cluster) =>
        _clients.GetOrAdd($"{cluster.Id}|{cluster.CertFingerprintSha256}", _ =>
            new HttpClient(_handlerFactory(cluster), disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan });

    /// <summary>
    /// Chama <c>/api2/json{path}</c> nos endpoints em ordem e devolve o campo "data".
    /// Falha de conexão (e timeout, se <paramref name="failoverOnTimeout"/>) passa ao próximo endpoint;
    /// qualquer resposta HTTP de erro vira <see cref="ProxmoxHttpException"/> sem failover.
    /// </summary>
    public async Task<JsonElement> SendAsync(
        ClusterConfig cluster,
        HttpMethod method,
        string path,
        IReadOnlyDictionary<string, string>? form,
        Action<HttpRequestMessage>? authorize,
        CancellationToken ct,
        TimeSpan? timeout = null,
        bool failoverOnTimeout = true)
    {
        if (cluster.Endpoints.Count == 0)
            throw new ProxmoxException($"Cluster '{cluster.Id}' sem endpoints.");

        var client = ClientFor(cluster);
        Exception? last = null;
        foreach (var endpoint in cluster.Endpoints)
        {
            using var req = new HttpRequestMessage(method, $"{endpoint.TrimEnd('/')}/api2/json{path}");
            authorize?.Invoke(req);
            if (form is not null)
                req.Content = new FormUrlEncodedContent(form);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout ?? TimeSpan.FromSeconds(30));
            try
            {
                using var resp = await client.SendAsync(req, cts.Token);
                var body = await resp.Content.ReadAsStringAsync(cts.Token);
                if (!resp.IsSuccessStatusCode)
                    throw new ProxmoxHttpException((int)resp.StatusCode, ErrorMessage(resp, body));

                using var doc = JsonDocument.Parse(body);
                return doc.RootElement.TryGetProperty("data", out var data) ? data.Clone() : NullElement;
            }
            catch (HttpRequestException e)
            {
                last = e;
            }
            catch (OperationCanceledException e) when (!ct.IsCancellationRequested)
            {
                last = e;
                if (!failoverOnTimeout)
                    throw new ProxmoxException($"Timeout em {path} ({cluster.Id}).", e);
            }
        }

        throw new ProxmoxException($"Nenhum endpoint do cluster '{cluster.Id}' respondeu: {last?.Message}", last);
    }

    private static string ErrorMessage(HttpResponseMessage resp, string body)
    {
        var text = resp.ReasonPhrase ?? "erro";
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String)
                text = m.GetString()!.Trim();
        }
        catch (JsonException) { }
        return $"PVE respondeu HTTP {(int)resp.StatusCode}: {text}";
    }
}
