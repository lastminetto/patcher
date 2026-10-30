namespace PvePatcher.Vuln;

/// <summary>Seção "Vuln" da configuração.</summary>
public sealed class VulnOptions
{
    public string DatabasePath { get; set; } = "/var/lib/pve-patcher/vuln.db";
    public string CacheDir { get; set; } = "/var/lib/pve-patcher/feeds";

    public string OsvBaseUrl { get; set; } = "https://osv-vulnerabilities.storage.googleapis.com";
    public string KevUrl { get; set; } = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    public string EpssUrl { get; set; } = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
    public string NvdUrl { get; set; } = "https://services.nvd.nist.gov/rest/json/cves/2.0";

    /// <summary>Janela do rate limit do NVD.</summary>
    public TimeSpan NvdWindow { get; set; } = TimeSpan.FromSeconds(30);
    public int NvdRequestsWithoutKey { get; set; } = 5;
    public int NvdRequestsWithKey { get; set; } = 50;

    /// <summary>
    /// Tempo máximo de consultas ao NVD dentro de um scan (a fila é serial). O que faltar fica para os próximos scans;
    /// até lá valem a severidade da distro, KEV e EPSS. Zero ou negativo = sem limite.
    /// </summary>
    public TimeSpan NvdBudgetPerScan { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>Quanto tempo esperar antes de consultar de novo um CVE que o NVD ainda não pontuou.</summary>
    public TimeSpan NvdRetryUnscored { get; set; } = TimeSpan.FromDays(3);
}
