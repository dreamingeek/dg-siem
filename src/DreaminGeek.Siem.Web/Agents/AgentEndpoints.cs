using System.Security.Claims;
using DreaminGeek.Siem.Core.Agents;
using DreaminGeek.Siem.Ingest;
using Microsoft.AspNetCore.Authentication.Certificate;

namespace DreaminGeek.Siem.Web.Agents;

public static class AgentEndpoints
{
    public const string AgentPolicy = "Agent";
    public const string AgentIdClaim = "dgsiem:agent_id";
    public const string TenantIdClaim = "dgsiem:tenant_id";
    public const string TenantSlugClaim = "dgsiem:tenant";

    /// <summary>Maps the agent API. Callers must restrict these to the agent port.</summary>
    public static void MapAgentApi(this IEndpointRouteBuilder app)
    {
        // Public CA certificate. Agents fetch it before enrolling and check it against the SHA-256 in
        // their token, so this endpoint needs no trust of its own.
        app.MapGet("/api/v1/agents/ca", (CertificateAuthority ca) => Results.Text(ca.CaCertificatePem, "application/x-pem-file"))
            .AllowAnonymous();

        // First contact: token + CSR in, certificate out. No client certificate yet.
        app.MapPost("/api/v1/agents/enroll", async (EnrollRequest request, AgentRegistry registry, CancellationToken ct) =>
        {
            try
            {
                return Results.Ok(await registry.EnrollAsync(request, ct));
            }
            catch (EnrollmentException ex)
            {
                return Results.Problem(ex.Message, statusCode: StatusCodes.Status403Forbidden);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                return Results.Problem("Invalid certificate signing request.", statusCode: StatusCodes.Status400BadRequest);
            }
        }).AllowAnonymous();

        // Install package for a new machine: needs an unused enrollment token (checked, not used up), which the
        // one-line install command carries along with the package's SHA-256.
        app.MapGet("/api/v1/agents/packages/{platform}", async (string platform, HttpRequest http, AgentRegistry registry, AgentPackageStore packages, CancellationToken ct) =>
        {
            var auth = http.Headers.Authorization.ToString();
            var token = auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? auth[7..].Trim() : null;
            if (token is null || !await registry.IsDownloadTokenValidAsync(token, ct))
            {
                return Results.Problem("Downloading the agent needs an unused enrollment token: Authorization: Bearer dgs1_...", statusCode: StatusCodes.Status401Unauthorized);
            }
            if (!AgentPackageStore.Platforms.Contains(platform) || packages.Latest(platform) is not { } package)
            {
                return Results.Problem($"No agent for {platform} has been uploaded (Administration > Agent updates).", statusCode: StatusCodes.Status404NotFound);
            }
            return Results.File(packages.PackagePath(package), package.IsWindows ? "application/zip" : "application/gzip", package.PackageFile);
        }).AllowAnonymous();

        var agent = app.MapGroup("/api/v1/agent").RequireAuthorization(AgentPolicy);

        // Automatic updates: 204 unless updates are on and a newer version for the agent's platform is uploaded.
        agent.MapGet("/update", async (string platform, ClaimsPrincipal user, HttpRequest http, AgentRegistry registry,
            AgentPackageStore packages, DreaminGeek.Siem.Alerting.SettingsStore settings, CancellationToken ct) =>
        {
            if (!AgentPackageStore.Platforms.Contains(platform))
            {
                return Results.NoContent();
            }
            var identity = Identity(user);
            await registry.SetPlatformAsync(identity, platform, ct);
            if (!(await settings.GetAgentUpdatesAsync(ct)).AutoUpdate || packages.Latest(platform) is not { } latest || !AgentPackageStore.IsNewer(latest.Version, AgentVersion(http)))
            {
                return Results.NoContent();
            }
            return Results.Ok(new AgentUpdateInfo(latest.Version, latest.Platform, latest.BinarySha256, latest.BinarySize));
        });

        agent.MapGet("/update/binary", (string platform, string version, AgentPackageStore packages) =>
            AgentPackageStore.Platforms.Contains(platform) && packages.Find(platform, version) is { } package
                ? Results.File(packages.BinaryPath(package), "application/octet-stream", package.BinaryName)
                : Results.NotFound());

        agent.MapGet("/config", async (ClaimsPrincipal user, AgentRegistry registry, HttpRequest http, CancellationToken ct) =>
        {
            var identity = Identity(user);
            await registry.TouchAsync(identity, AgentVersion(http), ct);
            registry.ReportStatus(identity.AgentId, AgentStatusReport.Parse(http.Headers[AgentStatusReport.Header]));
            return Results.Ok(await registry.GetConfigAsync(identity, ct));
        });

        agent.MapPost("/renew", async (RenewRequest request, ClaimsPrincipal user, AgentRegistry registry, CancellationToken ct) =>
        {
            try
            {
                return Results.Ok(await registry.RenewAsync(Identity(user), request, ct));
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                return Results.Problem("Invalid certificate signing request.", statusCode: StatusCodes.Status400BadRequest);
            }
        });

        // Batches arrive gzip-compressed (Content-Encoding: gzip); request decompression handles it.
        agent.MapPost("/ingest", async (AgentIngestBatch batch, ClaimsPrincipal user, IngestPipeline pipeline, AgentRegistry registry, HttpRequest http, CancellationToken ct) =>
        {
            var identity = Identity(user);
            await registry.TouchAsync(identity, AgentVersion(http), ct);
            if (!pipeline.Accepting)
            {
                // The event store is down or the queue is nearly full: the agent keeps the batch and retries.
                http.HttpContext.Response.Headers.RetryAfter = "30";
                return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
            }
            await pipeline.EnqueueAsync(identity.TenantSlug, batch.Events, ct);
            return Results.Accepted();
        });
    }

    /// <summary>Wires certificate authentication: chain must lead to our CA, then the thumbprint must match a live agent.</summary>
    public static IServiceCollection AddAgentAuthentication(this IServiceCollection services, Microsoft.AspNetCore.Authentication.AuthenticationBuilder auth)
    {
        ArgumentNullException.ThrowIfNull(auth);
        auth.AddCertificate(o =>
        {
            o.AllowedCertificateTypes = CertificateTypes.Chained;
            o.ChainTrustValidationMode = System.Security.Cryptography.X509Certificates.X509ChainTrustMode.CustomRootTrust;
            o.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
            o.ValidateCertificateUse = true;
            o.ValidateValidityPeriod = true;
            o.Events = new CertificateAuthenticationEvents
            {
                OnCertificateValidated = async context =>
                {
                    var registry = context.HttpContext.RequestServices.GetRequiredService<AgentRegistry>();
                    var identity = await registry.ResolveAsync(context.ClientCertificate, context.HttpContext.RequestAborted);
                    if (identity is null)
                    {
                        context.Fail("Unknown, replaced or revoked agent certificate.");
                        return;
                    }
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity(
                    [
                        new Claim(ClaimTypes.NameIdentifier, identity.AgentId.ToString()),
                        new Claim(ClaimTypes.Name, identity.Name),
                        new Claim(AgentIdClaim, identity.AgentId.ToString()),
                        new Claim(TenantIdClaim, identity.TenantId.ToString()),
                        new Claim(TenantSlugClaim, identity.TenantSlug),
                    ], CertificateAuthenticationDefaults.AuthenticationScheme));
                    context.Success();
                },
            };
        });

        services.AddOptions<CertificateAuthenticationOptions>(CertificateAuthenticationDefaults.AuthenticationScheme)
            .Configure<CertificateAuthority>((o, ca) =>
                o.CustomTrustStore.Add(System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(ca.CaCertificate.RawData)));

        services.AddAuthorizationBuilder().AddPolicy(AgentPolicy, p => p
            .AddAuthenticationSchemes(CertificateAuthenticationDefaults.AuthenticationScheme)
            .RequireClaim(AgentIdClaim));
        return services;
    }

    private static AgentIdentity Identity(ClaimsPrincipal user) => new(
        Guid.Parse(user.FindFirstValue(AgentIdClaim)!),
        user.Identity?.Name ?? string.Empty,
        Guid.Parse(user.FindFirstValue(TenantIdClaim)!),
        user.FindFirstValue(TenantSlugClaim)!);

    private static string? AgentVersion(HttpRequest http)
    {
        var ua = http.Headers.UserAgent.ToString();
        return ua.StartsWith("dg-siem-agent/", StringComparison.Ordinal) ? ua["dg-siem-agent/".Length..] : null;
    }
}
