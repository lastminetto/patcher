using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using PvePatcher.Core;

namespace PvePatcher.Web.Auth;

/// <summary>
/// Guarda o ticket do cookie em memória: o cookie leva só um id, as permissões (potencialmente grandes)
/// ficam no servidor. Reiniciar o serviço encerra as sessões.
/// </summary>
public sealed class MemoryTicketStore : ITicketStore
{
    private readonly ConcurrentDictionary<string, AuthenticationTicket> _tickets = new();

    public Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        Sweep();
        var key = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        _tickets[key] = ticket;
        return Task.FromResult(key);
    }

    public Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        _tickets[key] = ticket;
        return Task.CompletedTask;
    }

    public Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        if (_tickets.TryGetValue(key, out var t) && (t.Properties.ExpiresUtc is null || t.Properties.ExpiresUtc > DateTimeOffset.UtcNow))
            return Task.FromResult<AuthenticationTicket?>(t);
        return Task.FromResult<AuthenticationTicket?>(null);
    }

    public Task RemoveAsync(string key)
    {
        _tickets.TryRemove(key, out _);
        return Task.CompletedTask;
    }

    private void Sweep()
    {
        foreach (var (k, t) in _tickets)
            if (t.Properties.ExpiresUtc is { } e && e < DateTimeOffset.UtcNow) _tickets.TryRemove(k, out _);
    }
}

/// <summary>Passo 1 do login (usuário/senha) e passo 2 (TOTP). A senha nunca é guardada; só o ticket parcial, por até 5 min.</summary>
public sealed class LoginService(IProxmoxAuth auth, StateStore store, ILogger<LoginService> log)
{
    private sealed record Pending(string ClusterId, string UserId, string PartialTicket, DateTimeOffset Expires);

    private readonly ConcurrentDictionary<string, Pending> _pending = new();

    public sealed record LoginOutcome(UserInfo? User, string? TotpChallenge, string? Error);

    public async Task<LoginOutcome> LoginAsync(string clusterId, string userId, string password, CancellationToken ct)
    {
        var cluster = await store.GetClusterAsync(clusterId);
        if (cluster is null) return new(null, null, "Cluster desconhecido.");
        userId = userId.Trim();
        try
        {
            var r = await auth.LoginAsync(cluster.ToConfig(), userId, password, ct);
            switch (r.Status)
            {
                case PveLoginStatus.NeedTotp when r.Ticket is not null:
                    Sweep();
                    var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
                    _pending[token] = new Pending(clusterId, r.UserId ?? userId, r.Ticket, DateTimeOffset.UtcNow.AddMinutes(5));
                    return new(null, token, null);
                case PveLoginStatus.Success when r.Ticket is not null:
                    return await FinishAsync(cluster.ToConfig(), r.UserId ?? userId, r.Ticket, ct);
                default:
                    return new(null, null, r.Error ?? "Usuário ou senha inválidos.");
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "Falha no login em {Cluster}", clusterId);
            return new(null, null, "Não foi possível falar com o cluster: " + ex.Message);
        }
    }

    public async Task<LoginOutcome> CompleteTotpAsync(string challenge, string code, CancellationToken ct)
    {
        if (!_pending.TryGetValue(challenge, out var p) || p.Expires < DateTimeOffset.UtcNow)
            return new(null, null, "Sessão de login expirada; informe a senha novamente.");
        var cluster = await store.GetClusterAsync(p.ClusterId);
        if (cluster is null) return new(null, null, "Cluster desconhecido.");
        try
        {
            var r = await auth.CompleteTotpAsync(cluster.ToConfig(), p.UserId, p.PartialTicket, code.Trim(), ct);
            if (r.Status != PveLoginStatus.Success || r.Ticket is null)
                return new(null, challenge, r.Error ?? "Código inválido.");
            _pending.TryRemove(challenge, out _);
            return await FinishAsync(cluster.ToConfig(), r.UserId ?? p.UserId, r.Ticket, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "Falha no TOTP em {Cluster}", p.ClusterId);
            return new(null, challenge, "Falha ao validar o código: " + ex.Message);
        }
    }

    private async Task<LoginOutcome> FinishAsync(ClusterConfig cluster, string userId, string ticket, CancellationToken ct)
    {
        var perms = new PvePermissions(await auth.GetPermissionsAsync(cluster, ticket, ct));
        if (!perms.CanView)
            return new(null, null, "Este usuário não tem Sys.Audit em / no cluster; acesso negado.");
        return new(new UserInfo(cluster.Id, userId, perms), null, null);
    }

    private void Sweep()
    {
        foreach (var (k, p) in _pending)
            if (p.Expires < DateTimeOffset.UtcNow) _pending.TryRemove(k, out _);
    }
}

/// <summary>Usuário atual dentro de componentes interativos.</summary>
public sealed class CurrentUser(AuthenticationStateProvider provider)
{
    public async Task<UserInfo?> GetAsync() => UserInfo.FromPrincipal((await provider.GetAuthenticationStateAsync()).User);
}
