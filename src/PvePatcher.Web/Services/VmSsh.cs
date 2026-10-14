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

/// <summary>Monta o SshTarget (segredos do cofre, TOFU) e abre a sessão.</summary>
public sealed class VmSshService(
    StateStore store, SettingsService settings, ISecretStore vault, ITargetConnector connector, VmIpService ips) : IVmSessionProvider
{
    public async Task<ITargetSession> OpenAsync(VmKey key, Action<string>? log, CancellationToken ct)
    {
        var vm = await store.GetVmAsync(key) ?? throw new JobFailedException("VM não encontrada (removida do cluster?).");
        if (vm.State == ScanState.HostKeyChanged && vm.PendingHostKey is not null)
            throw new HostKeyBlockedException("A host key da VM mudou; aceite a nova chave na tela da VM antes de continuar.");

        var ip = ips.Resolve(vm);
        if (ip is null)
        {
            await store.UpdateVmAsync(key, v => v.LastError = "Sem IP para conectar");
            throw new JobFailedException("A VM não tem IP utilizável (guest agent sem resposta?). Defina um IP manual na aba Rede/SSH.");
        }

        var vmSecret = await vault.ReadAsync(SecretPaths.SshVm(key.ClusterId, key.VmId), ct);
        var secret = vmSecret is not null && vmSecret.ContainsKey(SecretPaths.PrivateKey)
            ? vmSecret
            : await vault.ReadAsync(SecretPaths.SshDefault, ct);
        if (secret is null || !secret.TryGetValue(SecretPaths.PrivateKey, out var priv) || string.IsNullOrWhiteSpace(priv))
            throw new JobFailedException("Chave SSH padrão não configurada. Gere ou cole uma em Configurações.");
        secret.TryGetValue(SecretPaths.Passphrase, out var pass);
        var user = vmSecret is not null && vmSecret.TryGetValue(SecretPaths.User, out var u) && !string.IsNullOrWhiteSpace(u)
            ? u : settings.Current.SshUser;

        var target = new SshTarget(ip.ToString(), vm.SshPort, user, priv, string.IsNullOrEmpty(pass) ? null : pass, vm.KnownHostKey);
        log?.Invoke($"Conectando em {user}@{ip}:{vm.SshPort}...");
        try
        {
            var session = await connector.ConnectAsync(target, ct);
            if (vm.KnownHostKey is null)
            {
                log?.Invoke($"Primeira conexão: host key {session.HostKeySha256} gravada (TOFU).");
                await store.UpdateVmAsync(key, v => v.KnownHostKey ??= session.HostKeySha256);
            }
            return session;
        }
        catch (HostKeyMismatchException ex)
        {
            await store.UpdateVmAsync(key, v =>
            {
                v.State = ScanState.HostKeyChanged;
                v.PendingHostKey = ex.Actual;
                v.LastError = "Host key mudou";
            });
            throw new HostKeyBlockedException($"Host key mudou: esperada {ex.Expected}, recebida {ex.Actual}. Scans e upgrades estão bloqueados até aceitar a nova chave.");
        }
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
            var cves = findings.Select(f => f.CveId).Distinct().ToList();
            if (cves.Count > 0)
            {
                try
                {
                    await feeds.EnrichAsync(cves, ct);
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
