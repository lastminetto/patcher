using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using PvePatcher.Core;
using PvePatcher.Integrations;
using PvePatcher.Targets;
using PvePatcher.Vuln;
using PvePatcher.Web.Components;
using PvePatcher.Web.Dev;

var builder = WebApplication.CreateBuilder(args);

// Config adicional do servidor (segredos de infraestrutura NÃO ficam aqui; só endereços e Bootstrap:Clusters).
builder.Configuration.AddJsonFile("/etc/pve-patcher/appsettings.Production.json", optional: true, reloadOnChange: false);

builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddCascadingAuthenticationState();

// --- Persistência (SQLite, WAL) ---
var dbPath = builder.Configuration["Data:Path"] ?? "/var/lib/pve-patcher/state.db";
var dbDir = Path.GetDirectoryName(Path.GetFullPath(dbPath));
if (!string.IsNullOrEmpty(dbDir)) Directory.CreateDirectory(dbDir);
// Chaves do cookie/antiforgery persistem junto ao banco (sem isso, cada restart invalida as sessões e formulários abertos).
if (!string.IsNullOrEmpty(dbDir)) builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(dbDir, "keys"))).SetApplicationName("pve-patcher");
builder.Services.AddDbContextFactory<AppDb>(o => o.UseSqlite($"Data Source={dbPath}"));
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<AppEvents>();
builder.Services.AddSingleton<SettingsService>();
builder.Services.AddSingleton<StateStore>();

// --- Autenticação via Proxmox (cookie com sessão em memória, 8 h) ---
var tickets = new MemoryTicketStore();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.Cookie.Name = "pve-patcher";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = SameSiteMode.Lax;
        o.ExpireTimeSpan = TimeSpan.FromHours(8);
        o.SlidingExpiration = false;
        o.LoginPath = "/login";
        o.SessionStore = tickets;
    });
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("View", p => p.RequireAuthenticatedUser().RequireAssertion(c => UserInfo.FromPrincipal(c.User)?.Permissions.CanView == true))
    .AddPolicy("Admin", p => p.RequireAuthenticatedUser().RequireAssertion(c => UserInfo.FromPrincipal(c.User)?.CanAdmin == true));
builder.Services.AddSingleton<LoginService>();
builder.Services.AddScoped<CurrentUser>();

// --- Aplicação ---
builder.Services.AddSingleton<VaultMonitor>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<VaultMonitor>());
builder.Services.AddSingleton<VmIpService>();
builder.Services.AddSingleton<VmSshService>();
builder.Services.AddSingleton<IVmSessionProvider>(sp => sp.GetRequiredService<VmSshService>());
builder.Services.AddSingleton<IVmScanner, VmScanService>();
builder.Services.AddSingleton<DiscoveryService>();
builder.Services.AddSingleton<SecretsService>();
builder.Services.AddSingleton<JobQueue>();
builder.Services.AddSingleton<IJobExecutor, JobExecutor>();
builder.Services.AddSingleton<OperationsService>();
builder.Services.AddSingleton<SchedulerService>();
builder.Services.AddHostedService<JobRunner>();
builder.Services.AddHostedService<DiscoveryBackgroundService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<SchedulerService>());

// === COMPOSIÇÃO DOS MÓDULOS ===
if (!builder.Configuration.GetValue<bool>("Dev:UseFakes"))
{
    builder.Services.AddPvePatcherIntegrations(builder.Configuration); // ISecretStore, IProxmoxClient, IProxmoxAuth, IIpSelector
    builder.Services.AddPvePatcherTargets(builder.Configuration);      // ITargetConnector, IHostScanner, IHostUpdater
    builder.Services.AddPvePatcherVuln(builder.Configuration);         // IVulnerabilityMatcher, IVulnFeedUpdater
}
else
{
    builder.Services.AddSingleton<FakeWorld>();
    builder.Services.AddSingleton<ISecretStore, FakeSecretStore>();
    builder.Services.AddSingleton<FakeProxmoxClient>();
    builder.Services.AddSingleton<IProxmoxClient>(sp => sp.GetRequiredService<FakeProxmoxClient>());
    builder.Services.AddSingleton<IProxmoxServicePermissions>(sp => sp.GetRequiredService<FakeProxmoxClient>());
    builder.Services.AddSingleton<IProxmoxAuth, FakeProxmoxAuth>();
    builder.Services.AddSingleton<IIpSelector, FakeIpSelector>();
    builder.Services.AddSingleton<ITargetConnector, FakeTargetConnector>();
    builder.Services.AddSingleton<IHostScanner, FakeHostScanner>();
    builder.Services.AddSingleton<IHostUpdater, FakeHostUpdater>();
    builder.Services.AddSingleton<IVulnerabilityMatcher, FakeVulnMatcher>();
    builder.Services.AddSingleton<IVulnFeedUpdater, FakeFeedUpdater>();
}

var app = builder.Build();

await DbInitializer.InitializeAsync(app.Services, app.Configuration);

// Atrás do nginx do OPNsense: respeitar X-Forwarded-*.
var fwd = new ForwardedHeadersOptions { ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost };
fwd.KnownIPNetworks.Clear();
fwd.KnownProxies.Clear();
app.UseForwardedHeaders(fwd);

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapStaticAssets();


app.MapPost("/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync();
    return Results.Redirect("/login");
});

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();

public partial class Program;
