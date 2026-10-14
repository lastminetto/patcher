using System.Text.Json;
using PvePatcher.Core;

namespace PvePatcher.Integrations.Proxmox;

/// <summary>Login de usuários da UI no PVE (ticket do usuário; o token de serviço não participa).</summary>
public sealed class ProxmoxAuth(PveHttp http) : IProxmoxAuth
{
    public async Task<PveLoginResult> LoginAsync(ClusterConfig cluster, string userId, string password, CancellationToken ct)
    {
        var form = new Dictionary<string, string> { ["username"] = userId, ["password"] = password };
        return await TicketAsync(cluster, form, "Usuário ou senha inválidos.", ct);
    }

    public async Task<PveLoginResult> CompleteTotpAsync(ClusterConfig cluster, string userId, string partialTicket, string totpCode, CancellationToken ct)
    {
        var form = new Dictionary<string, string>
        {
            ["username"] = userId,
            ["tfa-challenge"] = partialTicket,
            ["password"] = $"totp:{totpCode.Trim()}",
        };
        return await TicketAsync(cluster, form, "Código de verificação inválido ou expirado.", ct);
    }

    public async Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> GetPermissionsAsync(ClusterConfig cluster, string ticket, CancellationToken ct)
    {
        var data = await http.SendAsync(cluster, HttpMethod.Get, "/access/permissions", null,
            req => req.Headers.TryAddWithoutValidation("Cookie", $"PVEAuthCookie={ticket}"), ct);

        var result = new Dictionary<string, IReadOnlySet<string>>();
        if (data.ValueKind != JsonValueKind.Object)
            return result; // usuário sem privilégios: o PVE devolve {} (ou null)

        foreach (var path in data.EnumerateObject())
        {
            if (path.Value.ValueKind != JsonValueKind.Object)
                continue;
            result[path.Name] = path.Value.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
        }
        return result;
    }

    private async Task<PveLoginResult> TicketAsync(ClusterConfig cluster, Dictionary<string, string> form, string failedMessage, CancellationToken ct)
    {
        JsonElement data;
        try
        {
            data = await http.SendAsync(cluster, HttpMethod.Post, "/access/ticket", form, null, ct);
        }
        catch (ProxmoxHttpException e) when (e.StatusCode is 401 or 403)
        {
            return new PveLoginResult(PveLoginStatus.Failed, null, null, null, failedMessage);
        }

        var ticket = ProxmoxClient.Str(data, "ticket");
        if (string.IsNullOrEmpty(ticket))
            return new PveLoginResult(PveLoginStatus.Failed, null, null, null, failedMessage);

        var user = ProxmoxClient.Str(data, "username") ?? form["username"];
        if (ProxmoxClient.Int(data, "NeedTFA") == 1)
            return new PveLoginResult(PveLoginStatus.NeedTotp, user, ticket, null, null);

        return new PveLoginResult(PveLoginStatus.Success, user, ticket, ProxmoxClient.Str(data, "CSRFPreventionToken"), null);
    }
}
