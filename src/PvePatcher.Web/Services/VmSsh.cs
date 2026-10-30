using System.Net;
using PvePatcher.Core;

namespace PvePatcher.Web.Services;

/// <summary>IP efetivo de uma VM (override salvo + redes preferidas).</summary>
public sealed class VmIpService(IIpSelector selector, SettingsService settings)
{
    public IPAddress? Resolve(VmEntity vm) => Resolve(vm, settings.Current);

    public IPAddress? Resolve(VmEntity vm, AppSettings s)
    {
        var ov = vm.IpOverrideMode == IpOverrideMode.Auto ? null : new IpOverride(vm.IpOverrideMode, vm.IpOverrideValue);
        try { return selector.Select(vm.ToDiscovered(), ov, s.ParsePreferredNetworks()); }
        catch { return null; }
    }
}

/// <summary>
/// Monta o <see cref="SshTarget"/> de uma VM (IP efetivo, segredos do cofre, host key conhecida) e aplica o TOFU,
/// inclusive quando a host key muda (VM reinstalada/clonada): a nova é aceita e registrada no log.
/// Compartilhado pelo patcher (ssh/default) e pelo terminal (ssh/console).
/// </summary>
public sealed class VmConnectionResolver(
    StateStore store, SettingsService settings, ISecretStore vault, VmIpService ips, ILogger<VmConnectionResolver>? logger = null)
{
    /// <summary>Patcher: override por VM (ssh/vm/...) ou a chave padrão, com o usuário de Configurações.</summary>
    public async Task<SshTarget> ForPatcherAsync(VmKey key, CancellationToken ct)
    {
        var (vm, ip) = await LoadAsync(key, recordError: true);
        var vmSecret = await vault.ReadAsync(SecretPaths.SshVm(key.ClusterId, key.VmId), ct);
        var secret = vmSecret is not null && vmSecret.ContainsKey(SecretPaths.PrivateKey)
            ? vmSecret
            : await vault.ReadAsync(SecretPaths.SshDefault, ct);
        if (secret is null || !secret.TryGetValue(SecretPaths.PrivateKey, out var priv) || string.IsNullOrWhiteSpace(priv))
            throw new JobFailedException("Chave SSH padrão não configurada. Gere ou cole uma em Configurações.");
        var user = vmSecret is not null && vmSecret.TryGetValue(SecretPaths.User, out var u) && !string.IsNullOrWhiteSpace(u)
            ? u : settings.Current.SshUser;
        return Target(vm, ip, user, priv, secret);
    }

    /// <summary>Terminal: sempre a chave ssh/console e o usuário fixo de Configurações > Terminal SSH.</summary>
    public async Task<SshTarget> ForConsoleAsync(VmKey key, CancellationToken ct)
    {
        var (vm, ip) = await LoadAsync(key, recordError: false);
        var secret = await vault.ReadAsync(SecretPaths.SshConsole, ct);
        if (secret is null || !secret.TryGetValue(SecretPaths.PrivateKey, out var priv) || string.IsNullOrWhiteSpace(priv))
            throw new JobFailedException("Chave do terminal não configurada. Gere ou cole uma em Configurações > Terminal SSH.");
        var user = settings.Current.ConsoleUser;
        if (string.IsNullOrWhiteSpace(user))
            throw new JobFailedException("Usuário do terminal não configurado (Configurações > Terminal SSH).");
        return Target(vm, ip, user.Trim(), priv, secret);
    }

    /// <summary>
    /// Conecta com <paramref name="connect"/>; na primeira conexão grava a host key (TOFU). Se a host key mudou, aceita a
    /// nova automaticamente, registra a troca e reconecta.
    /// </summary>
    public async Task<T> ConnectAsync<T>(VmKey key, SshTarget target, Func<SshTarget, Task<T>> connect, Func<T, string> hostKeyOf, Action<string>? log)
    {
        try
        {
            var session = await connect(target);
            if (target.KnownHostKeySha256 is null)
            {
                var hk = hostKeyOf(session);
                log?.Invoke($"Primeira conexão: host key {hk} gravada (TOFU).");
                await store.UpdateVmAsync(key, v => v.KnownHostKey ??= hk);
            }
            return session;
        }
        catch (HostKeyMismatchException ex)
        {
            log?.Invoke($"Host key mudou ({ex.Expected} → {ex.Actual}); nova chave aceita automaticamente.");
            logger?.LogWarning("Host key de {Vm} mudou de {Old} para {New}; aceita automaticamente", key, ex.Expected, ex.Actual);
            await store.UpdateVmAsync(key, v => AcceptKey(v, ex.Actual));
            // Só uma nova tentativa: se a chave mudar de novo no meio, a exceção sobe como falha comum de conexão.
            try { return await connect(target with { KnownHostKeySha256 = ex.Actual }); }
            catch (HostKeyMismatchException again)
            {
                throw new JobFailedException($"Host key mudou de novo durante a reconexão ({again.Expected} → {again.Actual}).", again);
            }
        }
    }

    private static void AcceptKey(VmEntity v, string hostKey)
    {
        v.KnownHostKey = hostKey;
        v.PendingHostKey = null;
        if (v.State == ScanState.HostKeyChanged) { v.State = ScanState.None; v.LastError = null; }
    }

    private async Task<(VmEntity Vm, IPAddress Ip)> LoadAsync(VmKey key, bool recordError)
    {
        var vm = await store.GetVmAsync(key) ?? throw new JobFailedException("VM não encontrada (removida do cluster?).");
        if (vm.State == ScanState.HostKeyChanged && vm.PendingHostKey is not null)
        {
            // VMs que ficaram bloqueadas antes da aceitação automática: aceita a chave pendente e segue.
            logger?.LogWarning("Host key pendente de {Vm} ({New}) aceita automaticamente", key, vm.PendingHostKey);
            vm = await store.UpdateVmAsync(key, v => AcceptKey(v, v.PendingHostKey ?? v.KnownHostKey!))
                ?? throw new JobFailedException("VM não encontrada (removida do cluster?).");
        }

        var ip = ips.Resolve(vm);
        if (ip is null)
        {
            if (recordError) await store.UpdateVmAsync(key, v => v.LastError = "Sem IP para conectar");
            throw new JobFailedException("A VM não tem IP utilizável (guest agent sem resposta?). Defina um IP manual na aba Rede/SSH.");
        }
        return (vm, ip);
    }

    private static SshTarget Target(VmEntity vm, IPAddress ip, string user, string priv, IReadOnlyDictionary<string, string> secret)
    {
        secret.TryGetValue(SecretPaths.Passphrase, out var pass);
        secret.TryGetValue(SecretPaths.Certificate, out var cert);
        return new SshTarget(ip.ToString(), vm.SshPort, user, priv,
            string.IsNullOrEmpty(pass) ? null : pass, vm.KnownHostKey,
            string.IsNullOrWhiteSpace(cert) ? null : cert);
    }
}

/// <summary>Abre a sessão do patcher-agent numa VM.</summary>
public sealed class VmSshService(VmConnectionResolver resolver, ITargetConnector connector) : IVmSessionProvider
{
    public async Task<ITargetSession> OpenAsync(VmKey key, Action<string>? log, CancellationToken ct)
    {
        var target = await resolver.ForPatcherAsync(key, ct);
        log?.Invoke($"Conectando em {target.User}@{target.Host}:{target.Port}...");
        return await resolver.ConnectAsync(key, target, t => connector.ConnectAsync(t, ct), s => s.HostKeySha256, log);
    }
}

/// <summary>Scan de uma VM + cruzamento com CVEs + gravação do estado.</summary>
public sealed class VmScanService(
    StateStore store, SettingsService settings, IVmSessionProvider sessions, IHostScanner scanner,
    IVulnerabilityMatcher matcher, IVulnFeedUpdater feeds, ILogger<VmScanService> logger) : IVmScanner
{
    public async Task<ScanSummary> ScanAsync(VmKey key, Action<string> log, CancellationToken ct)
    {
        try
        {
            HostScan scan;
            await using (var session = await sessions.OpenAsync(key, log, ct))
            {
                log("Coletando pacotes e atualizações pendentes...");
                scan = await scanner.ScanAsync(session, log, ct);
            }

            var th = settings.Current.Thresholds;
            log($"{scan.Installed.Count} pacotes instalados, {scan.Pending.Count} atualização(ões) pendente(s). Cruzando com CVEs...");
            var findings = await matcher.MatchAsync(scan, th, ct);
            // Só as corrigíveis vão ao NVD: as Unfixed do Debian passam de centenas por host e, no rate limit
            // sem key (5 req/30 s), travariam a fila serial por horas. As que a atualização pendente corrige vão primeiro,
            // porque o NVD tem tempo máximo por scan e o resto fica para os próximos.
            var cves = findings.Where(f => f.Status != FindingStatus.Unfixed)
                .OrderBy(f => f.Status == FindingStatus.FixedByPendingUpdate ? 0 : 1)
                .Select(f => f.CveId).Distinct().ToList();
            if (cves.Count > 0)
            {
                try
                {
                    await feeds.EnrichAsync(cves, log, ct);
                    findings = await matcher.MatchAsync(scan, th, ct);
                }
                catch (Exception ex) when (ex is not OperationCanceledException and not VaultUnavailableException)
                {
                    log($"Aviso: enriquecimento NVD falhou ({ex.Message}); usando dados já locais.");
                }
            }

            var saved = await store.UpdateVmAsync(key, v => v.ApplyScan(scan, findings));
            if (saved is null) throw new JobFailedException("A VM foi removida do cluster durante o scan.");
            var fixable = findings.Where(f => f.Status == FindingStatus.FixedByPendingUpdate).Select(f => f.CveId).Distinct().Count();
            log($"Concluído: {fixable} CVE(s) corrigível(is) pelas atualizações pendentes.");
            return new ScanSummary(scan.Pending.Count, fixable, scan.RebootRequired);
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not VaultUnavailableException and not HostKeyBlockedException)
        {
            if (ex is not JobFailedException) logger.LogWarning(ex, "Scan de {Vm} falhou", key);
            await store.UpdateVmAsync(key, v => { v.State = ScanState.Error; v.LastError = ex.Message; });
            throw ex as JobFailedException ?? new JobFailedException(ex.Message, ex);
        }
    }
}
