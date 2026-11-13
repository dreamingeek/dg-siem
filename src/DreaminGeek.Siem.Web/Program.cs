using Microsoft.Extensions.DependencyInjection.Extensions;
using DreaminGeek.Siem.Alerting;
using DreaminGeek.Siem.Data;
using DreaminGeek.Siem.Data.Entities;
using DreaminGeek.Siem.Ingest;
using DreaminGeek.Siem.Storage.ClickHouse;
using DreaminGeek.Siem.Web;
using DreaminGeek.Siem.Web.Agents;
using DreaminGeek.Siem.Web.Components;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Npgsql;

var builder = WebApplication.CreateBuilder(args);
var isAdminCommand = AdminCli.IsCommand(args);
if (isAdminCommand)
{
    // Keep stdout clean for command output (e.g. `token create` prints only the token).
    builder.Logging.ClearProviders();
    builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);
    builder.Logging.SetMinimumLevel(LogLevel.Warning);
    builder.Logging.AddFilter("Microsoft.EntityFrameworkCore", LogLevel.None);
}

var httpPort = builder.Configuration.GetValue("Server:HttpPort", 8080);
var agentPort = builder.Configuration.GetValue("Server:AgentPort", 8443);

// Metadata (users, tenants, agents, saved searches, dashboards, alerts) → PostgreSQL.
var postgres = new NpgsqlConnectionStringBuilder(builder.Configuration.GetConnectionString("Postgres"));
if (!postgres.ContainsKey("Gss Encryption Mode"))
{
    // Npgsql tries Kerberos/GSS first by default; the container has no Kerberos libraries and we use
    // password auth, so skip it unless the operator asks for it in the connection string.
    postgres.GssEncryptionMode = GssEncryptionMode.Disable;
}
builder.Services.AddDbContextFactory<SiemDbContext>(o => o.UseNpgsql(postgres.ConnectionString));

// Keys that protect login cookies and antiforgery tokens. Persisted next to the PKI so sign-ins
// survive container rebuilds.
builder.Services.AddDataProtection()
    .SetApplicationName("dg-siem")
    .PersistKeysToFileSystem(new DirectoryInfo(builder.Configuration.GetValue("Server:KeysDirectory", "/var/lib/dg-siem/keys")!));

// Agent PKI. The CA lives in Pki:Directory; back it up.
builder.Services.Configure<PkiOptions>(builder.Configuration.GetSection(PkiOptions.SectionName));
builder.Services.AddSingleton<CertificateAuthority>();
builder.Services.AddSingleton<AgentRegistry>();
builder.Services.Configure<AgentPackageOptions>(builder.Configuration.GetSection(AgentPackageOptions.SectionName));
builder.Services.AddSingleton<AgentPackageStore>();
builder.Services.AddSingleton<AgentHealth>();
builder.Services.AddSingleton<DreaminGeek.Siem.Web.Features.FeatureState>();
builder.Services.AddSingleton<DreaminGeek.Siem.Alerting.IHealthAlertSource, DreaminGeek.Siem.Web.Health.HealthAlertSource>();
builder.Services.AddSingleton<DreaminGeek.Siem.Web.Admin.AdminService>();
builder.Services.AddMemoryCache();
// Nightly backups (Administration > Backups, `dg-siem-server backup ...`).
builder.Services.Configure<DreaminGeek.Siem.Web.Backups.BackupOptions>(builder.Configuration.GetSection(DreaminGeek.Siem.Web.Backups.BackupOptions.SectionName));
builder.Services.AddSingleton<DreaminGeek.Siem.Web.Backups.BackupService>();
if (isAdminCommand)
{
    // `backup now|restore` talk to ClickHouse; the host isn't started, so no background services run.
    builder.Services.AddDgSiemClickHouse(builder.Configuration);
    builder.Services.AddDgSiemAlerting();
}

// Local logins (UI in Phase 2) + certificate auth for agents.
builder.Services.AddIdentityCore<SiemUser>(o =>
    {
        o.Password.RequiredLength = 12;
        o.User.RequireUniqueEmail = true;
        o.Lockout.MaxFailedAccessAttempts = 5;
        o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
        o.Lockout.AllowedForNewUsers = true;
    })
    .AddRoles<IdentityRole<Guid>>()
    .AddEntityFrameworkStores<SiemDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();
var auth = builder.Services.AddAuthentication(IdentityConstants.ApplicationScheme);
auth.AddIdentityCookies(cookies =>
{
    // Between the password and the authenticator code.
    cookies.TwoFactorUserIdCookie?.Configure(o =>
    {
        o.Cookie.Name = "dgsiem.2fa";
        o.Cookie.HttpOnly = true;
        o.ExpireTimeSpan = TimeSpan.FromMinutes(5);
    });
    // "Don't ask again on this browser".
    cookies.TwoFactorRememberMeCookie?.Configure(o =>
    {
        o.Cookie.Name = "dgsiem.2fa-remember";
        o.Cookie.HttpOnly = true;
        o.ExpireTimeSpan = TimeSpan.FromDays(14);
    });
});
// Sessions re-check the account every minute, so a password reset, two-factor change or access change
// signs out other browsers promptly. Open tabs (Blazor circuits) get the same check from the provider below.
builder.Services.Configure<SecurityStampValidatorOptions>(o => o.ValidationInterval = DreaminGeek.Siem.Web.Security.RevalidatingIdentityStateProvider.Interval);
builder.Services.ConfigureApplicationCookie(o =>
{
    o.LoginPath = "/account/login";
    o.LogoutPath = "/account/logout";
    o.AccessDeniedPath = "/account/login";
    o.Cookie.Name = "dgsiem.auth";
    o.Cookie.HttpOnly = true;
    o.Cookie.SameSite = SameSiteMode.Lax;
    o.ExpireTimeSpan = TimeSpan.FromHours(12);
    o.SlidingExpiration = true;
    // APIs get a 401/403, not a redirect to the login page.
    o.Events.OnRedirectToLogin = ctx =>
    {
        if (ctx.Request.Path.StartsWithSegments("/api"))
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        }
        ctx.Response.Redirect(ctx.RedirectUri);
        return Task.CompletedTask;
    };
    o.Events.OnRedirectToAccessDenied = ctx =>
    {
        ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    };
});
builder.Services.AddAgentAuthentication(auth);
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<Microsoft.AspNetCore.Components.Authorization.AuthenticationStateProvider, DreaminGeek.Siem.Web.Security.RevalidatingIdentityStateProvider>();
builder.Services.AddSingleton<DreaminGeek.Siem.Web.Security.TenantAccess>();

if (!isAdminCommand)
{
    // Two listeners: plain HTTP for the UI (put it behind your reverse proxy), and the agent
    // port with its own TLS + client certificates (expose it as raw TCP, never TLS-terminated).
    builder.WebHost.ConfigureKestrel((context, kestrel) =>
    {
        kestrel.ListenAnyIP(httpPort);
        kestrel.ListenAnyIP(agentPort, listen => listen.UseAgentTls(kestrel.ApplicationServices.GetRequiredService<CertificateAuthority>()));
    });

    // Drop rules (PostgreSQL) applied by the ingest pipeline before storage.
    builder.Services.AddSingleton<DbDropRuleSource>();
    builder.Services.AddSingleton<DreaminGeek.Siem.Ingest.IDropRuleSource>(sp => sp.GetRequiredService<DbDropRuleSource>());
    builder.Services.AddHostedService(sp => sp.GetRequiredService<DbDropRuleSource>());

    // Events → ClickHouse.
    builder.Services.AddDgSiemClickHouse(builder.Configuration);
    builder.Services.AddDgSiemIngest(builder.Configuration);
    // GeoIP: lookups at ingest, databases kept current in the background.
    builder.Services.AddSingleton<DreaminGeek.Siem.Ingest.GeoIp.GeoIpEnricher>();
    builder.Services.Replace(ServiceDescriptor.Singleton<DreaminGeek.Siem.Ingest.GeoIp.IGeoIpEnricher>(sp => sp.GetRequiredService<DreaminGeek.Siem.Ingest.GeoIp.GeoIpEnricher>()));
    builder.Services.AddHttpClient(DreaminGeek.Siem.Web.GeoIp.GeoIpUpdater.HttpClientName, http => http.Timeout = TimeSpan.FromMinutes(5));
    builder.Services.AddSingleton<DreaminGeek.Siem.Web.GeoIp.GeoIpUpdater>();
    builder.Services.AddHostedService(sp => sp.GetRequiredService<DreaminGeek.Siem.Web.GeoIp.GeoIpUpdater>());
    builder.Services.AddDgSiemAlerting();
    // Threat intel (off until switched on under Administration > Features).
    builder.Services.AddSingleton<DreaminGeek.Siem.Ingest.ThreatIntel.ThreatIntelEnricher>();
    builder.Services.AddSingleton<DreaminGeek.Siem.Ingest.ThreatIntel.IThreatIntelEnricher>(sp => sp.GetRequiredService<DreaminGeek.Siem.Ingest.ThreatIntel.ThreatIntelEnricher>());
    builder.Services.AddHttpClient(DreaminGeek.Siem.Web.ThreatIntel.ThreatIntelService.HttpClientName, http =>
    {
        http.Timeout = TimeSpan.FromMinutes(2);
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"DG-SIEM/{typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "0"}");
    });
    builder.Services.AddSingleton<DreaminGeek.Siem.Web.ThreatIntel.ThreatIntelService>();
    builder.Services.AddHostedService(sp => sp.GetRequiredService<DreaminGeek.Siem.Web.ThreatIntel.ThreatIntelService>());
    // Retention rules (ingest + table TTL) and the cold tier; loaded at startup.
    builder.Services.AddSingleton<DreaminGeek.Siem.Web.Storage.ColdStorageService>();
    builder.Services.AddSingleton<DreaminGeek.Siem.Web.Storage.RetentionService>();
    builder.Services.AddSingleton<DreaminGeek.Siem.Web.Health.HealthService>();
    builder.Services.AddHostedService(sp => sp.GetRequiredService<DreaminGeek.Siem.Web.Storage.RetentionService>());
    builder.Services.AddHostedService(sp => sp.GetRequiredService<DreaminGeek.Siem.Web.Backups.BackupService>());
    builder.Services.AddSingleton<DreaminGeek.Siem.Web.Security.TwoFactorPolicy>();
    builder.Services.AddRequestDecompression();
    builder.Services.AddSingleton<DreaminGeek.Siem.Web.Search.SearchService>();
    builder.Services.AddSingleton<DreaminGeek.Siem.Web.Search.SavedSearchService>();
    builder.Services.AddSingleton<DreaminGeek.Siem.Web.Search.SuggestService>();
    builder.Services.AddSingleton<DreaminGeek.Siem.Web.Alerts.AlertAdminService>();
    builder.Services.AddSingleton<DreaminGeek.Siem.Web.Dashboards.DashboardService>();

    builder.Services.AddRazorComponents()
        .AddInteractiveServerComponents();
}

var app = builder.Build();

await using (var scope = app.Services.CreateAsyncScope())
{
    await scope.ServiceProvider.GetRequiredService<SiemDbContext>().Database.MigrateAsync();
}

if (isAdminCommand)
{
    return await AdminCli.RunAsync(app.Services, args);
}

var clickHouseOptions = app.Services.GetRequiredService<IOptions<ClickHouseOptions>>().Value;
if (clickHouseOptions.ApplyMigrations)
{
    await app.Services.GetRequiredService<ClickHouseMigrator>().MigrateAsync(CancellationToken.None);
}
if (clickHouseOptions.EnforceRowPolicies)
{
    // Second isolation layer: ClickHouse row policies per tenant, verified by a self-test.
    // On failure search is disabled (logged as Critical); ingest keeps working.
    await using var policyScope = app.Services.CreateAsyncScope();
    var slugs = await policyScope.ServiceProvider.GetRequiredService<SiemDbContext>().Tenants.Select(t => t.Slug).ToListAsync();
    await app.Services.GetRequiredService<TenantRowPolicies>().InitializeAsync(slugs, CancellationToken.None);
}
_ = app.Services.GetRequiredService<CertificateAuthority>().ServerCertificate; // create CA/cert at startup, not on first agent

// The agent port serves only the agent API; the UI port never serves it.
app.Use(async (context, next) =>
{
    var onAgentPort = context.Connection.LocalPort == agentPort;
    var isAgentApi = context.Request.Path.StartsWithSegments("/api/v1/agent") || context.Request.Path.StartsWithSegments("/api/v1/agents");
    if (onAgentPort != isAgentApi)
    {
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        return;
    }
    await next(context);
});

// HTML error pages are for the UI only; APIs must return their real status codes
// (a re-executed 403 would otherwise turn into a 400 from the UI's antiforgery check).
app.UseWhen(context => context.Connection.LocalPort != agentPort && !context.Request.Path.StartsWithSegments("/api"), ui =>
{
    if (!app.Environment.IsDevelopment())
    {
        ui.UseExceptionHandler("/Error", createScopeForErrors: true);
    }
    ui.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
});

app.UseRequestDecompression();
app.UseAuthentication();
app.UseAuthorization();
// "Require two-factor": signed-in users without an authenticator go to their account page first.
app.UseWhen(context => context.Connection.LocalPort != agentPort, ui => ui.Use(async (context, next) =>
{
    if (context.User.Identity?.IsAuthenticated == true
        && !DreaminGeek.Siem.Web.Security.TwoFactor.AllowedWithoutTwoFactor(context.Request.Path)
        && !await context.RequestServices.GetRequiredService<DreaminGeek.Siem.Web.Security.TwoFactorPolicy>().IsSatisfiedAsync(context))
    {
        if (context.Request.Path.StartsWithSegments("/api"))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }
        context.Response.Redirect($"{context.Request.PathBase}{DreaminGeek.Siem.Web.Security.TwoFactorPolicy.SetupPath}?required=1");
        return;
    }
    await next();
}));
app.UseAntiforgery();

app.MapGet("/healthz", () => Results.Ok(new { status = "ok" })).AllowAnonymous();
// After a password or two-factor change (which updates the security stamp), re-issue this browser's
// sign-in so it isn't signed out at the next check. Only refreshes the caller's own session.
app.MapGet("/account/refresh", async (string? returnUrl, HttpContext context, SignInManager<SiemUser> signIn, UserManager<SiemUser> users) =>
{
    if (await users.GetUserAsync(context.User) is { } user)
    {
        await signIn.RefreshSignInAsync(user);
    }
    return Results.LocalRedirect(DreaminGeek.Siem.Web.Security.ReturnUrls.Safe(returnUrl));
}).RequireAuthorization();
app.MapPost("/account/logout", async (SignInManager<SiemUser> signIn) =>
{
    await signIn.SignOutAsync();
    return Results.LocalRedirect("/account/login");
});
// Agent packages for an admin to download from the Agent updates page (UI port, global admins only).
app.MapGet("/admin/agent-packages/{platform}/{version}", async (string platform, string version, HttpContext context,
    DreaminGeek.Siem.Web.Security.TenantAccess access, AgentPackageStore packages) =>
{
    if ((await access.GetAsync(context.User, context.RequestAborted))?.IsGlobalAdmin != true)
    {
        return Results.Forbid();
    }
    return AgentPackageStore.Platforms.Contains(platform) && packages.Find(platform, version) is { } package
        ? Results.File(packages.PackagePath(package), package.IsWindows ? "application/zip" : "application/gzip", package.PackageFile)
        : Results.NotFound();
}).RequireAuthorization();
app.MapAgentApi();
DreaminGeek.Siem.Web.Search.SearchEndpoints.MapSearchApi(app);

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

await app.RunAsync();
return 0;
