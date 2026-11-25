using System.Security.Claims;
using System.Text;
using DreaminGeek.Siem.Alerting;
using DreaminGeek.Siem.Data.Entities;
using DreaminGeek.Siem.Web.Admin;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace DreaminGeek.Siem.Web.Security;

/// <summary>
/// Single sign-on through an OpenID Connect provider (Authentik, or any other). Accounts are still added in
/// Administration &gt; Users: nobody gets in just by having an account at the provider. Each person links their
/// provider account once from their account page; after that the provider's account ID identifies them. An email
/// the provider marks as verified links on first sign-in by itself. The provider does the second factor, so a
/// single sign-on session counts as two-factor done.
/// </summary>
public static class Sso
{
    /// <summary>The authentication scheme, the login provider name in AspNetUserLogins, and the sign-in's
    /// <see cref="ClaimTypes.AuthenticationMethod"/>.</summary>
    public const string Scheme = "oidc";
    public const string CallbackPath = "/signin-oidc";

    private const string ModeKey = "dgsiem.mode";
    private const string UserKey = "dgsiem.user";
    private const string ReturnKey = "dgsiem.return";

    /// <summary>This session was signed in through single sign-on (the provider did the second factor).</summary>
    public static bool SignedInWithSso(ClaimsPrincipal principal) =>
        principal?.HasClaim(ClaimTypes.AuthenticationMethod, Scheme) == true;

    /// <summary>The redirect URI to register at the provider: the public URL when one is set (behind a TLS proxy
    /// the request itself says http), else the address this request came in on.</summary>
    public static string RedirectUri(string? publicUrl, string requestBase) =>
        (string.IsNullOrWhiteSpace(publicUrl) ? requestBase : publicUrl).TrimEnd('/') + CallbackPath;

    public static void MapSsoEndpoints(this IEndpointRouteBuilder app)
    {
        // Start signing in.
        app.MapGet("/account/sso", (string? returnUrl, SsoService sso) =>
        {
            if (!sso.Current.Ready)
            {
                return Results.LocalRedirect("/account/login");
            }
            var props = new AuthenticationProperties { RedirectUri = "/account/sso/done" };
            props.Items[ModeKey] = "signin";
            props.Items[ReturnKey] = ReturnUrls.Safe(returnUrl);
            return Results.Challenge(props, [Scheme]);
        }).AllowAnonymous();

        // Link the signed-in account (who has already passed password and two-factor) to their provider account.
        app.MapGet("/account/sso/link", (HttpContext context, SsoService sso) =>
        {
            var id = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!sso.Current.Ready || id is null)
            {
                return Results.LocalRedirect("/account/security");
            }
            var props = new AuthenticationProperties { RedirectUri = "/account/sso/done" };
            props.Items[ModeKey] = "link";
            props.Items[UserKey] = id;
            return Results.Challenge(props, [Scheme]);
        }).RequireAuthorization();

        app.MapGet("/account/sso/done", DoneAsync).AllowAnonymous();
    }

    private static async Task<IResult> DoneAsync(HttpContext context, UserManager<SiemUser> users, SignInManager<SiemUser> signIn,
        SsoService sso, ILoggerFactory loggers)
    {
        var log = loggers.CreateLogger(typeof(Sso).FullName!);
        var external = await context.AuthenticateAsync(IdentityConstants.ExternalScheme);
        await context.SignOutAsync(IdentityConstants.ExternalScheme);
        if (!external.Succeeded || external.Principal is null || external.Properties is null)
        {
            return Results.LocalRedirect("/account/login?sso=failed");
        }
        var p = external.Principal;
        var sub = p.FindFirstValue("sub");
        if (string.IsNullOrEmpty(sub))
        {
            return Results.LocalRedirect("/account/login?sso=failed");
        }
        var email = p.FindFirstValue("email");
        var verified = string.Equals(p.FindFirstValue("email_verified"), "true", StringComparison.OrdinalIgnoreCase);
        var who = p.FindFirstValue("preferred_username") ?? email ?? sub;
        var label = sso.Current.ButtonLabel;

        if (Item(external.Properties, ModeKey) == "link")
        {
            // Only the account that started the link, and only in a browser still signed in as it.
            var meId = Item(external.Properties, UserKey);
            var me = meId is not null && meId == context.User.FindFirstValue(ClaimTypes.NameIdentifier) ? await users.FindByIdAsync(meId) : null;
            if (me is null)
            {
                return Results.LocalRedirect("/account/security?sso=failed");
            }
            if (await users.FindByLoginAsync(Scheme, sub) is { } other && other.Id != me.Id)
            {
                SsoLog.LinkTaken(log, who, other.Email);
                return Results.LocalRedirect("/account/security?sso=taken");
            }
            foreach (var old in (await users.GetLoginsAsync(me)).Where(l => l.LoginProvider == Scheme).ToList())
            {
                await users.RemoveLoginAsync(me, old.LoginProvider, old.ProviderKey);
            }
            if (!(await users.AddLoginAsync(me, new UserLoginInfo(Scheme, sub, who))).Succeeded)
            {
                return Results.LocalRedirect("/account/security?sso=failed");
            }
            SsoLog.Linked(log, me.Email, label, who);
            return Results.LocalRedirect("/account/security?sso=linked");
        }

        var user = await users.FindByLoginAsync(Scheme, sub);
        if (user is null && verified && !string.IsNullOrEmpty(email) && await users.FindByEmailAsync(email) is { } byEmail
            && !(await users.GetLoginsAsync(byEmail)).Any(l => l.LoginProvider == Scheme))
        {
            // The provider vouches for the address: link on first use.
            await users.AddLoginAsync(byEmail, new UserLoginInfo(Scheme, sub, who));
            SsoLog.LinkedByEmail(log, byEmail.Email, label, who);
            user = byEmail;
        }
        if (user is null)
        {
            SsoLog.NotLinked(log, label, who, sub);
            return Results.LocalRedirect("/account/login?sso=unlinked");
        }
        if (await users.IsLockedOutAsync(user))
        {
            SsoLog.Refused(log, user.Email, "the account is locked");
            return Results.LocalRedirect("/account/login?sso=locked");
        }

        await signIn.SignInAsync(user, isPersistent: false, authenticationMethod: Scheme);
        SsoLog.SignedIn(log, user.Email, label, who);
        return Results.LocalRedirect(ReturnUrls.Safe(Item(external.Properties, ReturnKey)));
    }

    private static string? Item(AuthenticationProperties p, string key) => p.Items.TryGetValue(key, out var v) ? v : null;
}

/// <summary>Loads, checks and saves the single sign-on settings, and keeps the sign-in options in step with them.</summary>
public sealed class SsoService(SettingsStore settings, TenantAccess access, IOptionsMonitorCache<OpenIdConnectOptions> oidcCache, IHttpClientFactory http)
{
    public const string HttpClientName = "sso";

    public SsoSettings Current { get; private set; } = SsoSettings.Default;

    public async Task LoadAsync(CancellationToken ct)
    {
        Current = await settings.GetSsoAsync(ct);
        oidcCache.TryRemove(Sso.Scheme); // the next sign-in builds its options from these settings
    }

    /// <summary>The public URL from Administration &gt; Notifications, used for the redirect URI.</summary>
    public async Task<string?> PublicUrlAsync(CancellationToken ct) => (await settings.GetGeneralAsync(ct)).PublicUrl;

    /// <param name="s">A null client secret keeps the saved one.</param>
    /// <returns>The settings as saved (address normalized).</returns>
    public async Task<SsoSettings> SaveAsync(UserAccess? caller, SsoSettings s, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can set up single sign-on.", ct);
        ArgumentNullException.ThrowIfNull(s);
        s = Validate(s, s.ClientSecret ?? Current.ClientSecret);
        if (s.Enabled)
        {
            await CheckProviderAsync(s.Authority!, ct);
        }
        await settings.SaveSsoAsync(s, ct);
        await LoadAsync(ct);
        return Current;
    }

    /// <summary>Trims and checks the settings. Throws <see cref="AdminException"/> with what to fix.</summary>
    public static SsoSettings Validate(SsoSettings s, string? effectiveSecret)
    {
        ArgumentNullException.ThrowIfNull(s);
        static string? T(string? v) => string.IsNullOrWhiteSpace(v) ? null : v.Trim();
        var authority = T(s.Authority);
        if (authority is not null)
        {
            if (!Uri.TryCreate(authority, UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http") || !string.IsNullOrEmpty(uri.Query))
            {
                throw new AdminException("The provider address must be a web address starting with https://.");
            }
            if (!authority.EndsWith('/'))
            {
                authority += "/";
            }
        }
        s = s with { Authority = authority, ClientId = T(s.ClientId), ClientSecret = s.ClientSecret is null ? null : T(s.ClientSecret), Label = T(s.Label) };
        if (s.Label is { Length: > 40 })
        {
            throw new AdminException("Keep the button name under 40 characters.");
        }
        if (s.Enabled && (s.Authority is null || s.ClientId is null || string.IsNullOrWhiteSpace(effectiveSecret)))
        {
            throw new AdminException("Enter the provider address, client ID and client secret before turning single sign-on on.");
        }
        return s;
    }

    /// <summary>Reads the provider's discovery document: it must answer and call itself by the same address.</summary>
    private async Task CheckProviderAsync(string authority, CancellationToken ct)
    {
        var url = authority + ".well-known/openid-configuration";
        OpenIdConnectConfiguration doc;
        try
        {
            using var client = http.CreateClient(HttpClientName);
            doc = OpenIdConnectConfiguration.Create(await client.GetStringAsync(new Uri(url), ct));
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or ArgumentException or System.Text.Json.JsonException)
        {
            throw new AdminException($"Couldn't read {url} from this server: {ex.Message}");
        }
        if (!string.Equals(doc.Issuer?.TrimEnd('/'), authority.TrimEnd('/'), StringComparison.Ordinal))
        {
            throw new AdminException($"The provider calls itself {doc.Issuer}, not {authority}. Use the issuer address it shows.");
        }
        if (string.IsNullOrEmpty(doc.AuthorizationEndpoint) || string.IsNullOrEmpty(doc.TokenEndpoint))
        {
            throw new AdminException("The provider's settings are missing its sign-in or token address.");
        }
    }
}

/// <summary>Builds the OpenID Connect options from the saved settings (rebuilt after each save).</summary>
public sealed class SsoOptionsSetup(SsoService sso) : IConfigureNamedOptions<OpenIdConnectOptions>
{
    public void Configure(string? name, OpenIdConnectOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (name != Sso.Scheme)
        {
            return;
        }
        var s = sso.Current;
        // Something valid even when it's off, so the handler can be built; the sign-in is refused before it's used.
        options.Authority = s.Authority ?? "https://sso.invalid/";
        options.ClientId = s.ClientId ?? "unset";
        options.ClientSecret = s.ClientSecret;
        options.RequireHttpsMetadata = options.Authority.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        options.SignInScheme = IdentityConstants.ExternalScheme;
        options.CallbackPath = Sso.CallbackPath;
        options.ResponseType = OpenIdConnectResponseType.Code;
        options.UsePkce = true;
        // The answer comes back as a plain redirect, so Lax cookies are enough (no cross-site POST needing SameSite=None).
        options.ResponseMode = OpenIdConnectResponseMode.Query;
        options.CorrelationCookie.SameSite = SameSiteMode.Lax;
        options.NonceCookie.SameSite = SameSiteMode.Lax;
        options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.NonceCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        options.GetClaimsFromUserInfoEndpoint = true;
        // The user-info answer only keeps a few claims by default: a verified email links by itself, and the
        // username names the link.
        options.ClaimActions.MapUniqueJsonKey("email_verified", "email_verified");
        options.ClaimActions.MapUniqueJsonKey("preferred_username", "preferred_username");
        options.MapInboundClaims = false;
        options.SaveTokens = false;
        options.RemoteAuthenticationTimeout = TimeSpan.FromMinutes(10);
        // Authentik signs with the client secret (HS256) when the provider has no signing key; allow that too.
        if (s.ClientSecret is { Length: >= 32 } secret)
        {
            options.TokenValidationParameters.IssuerSigningKeys = [new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret))];
        }
        options.TokenValidationParameters.NameClaimType = "name";
        options.Events.OnRedirectToIdentityProvider = async context =>
        {
            // Behind a TLS proxy the request says http://; the provider must send people back to the public address.
            var publicUrl = await context.HttpContext.RequestServices.GetRequiredService<SsoService>().PublicUrlAsync(context.HttpContext.RequestAborted);
            if (!string.IsNullOrWhiteSpace(publicUrl))
            {
                // The handler stores this one after the event, and redeems the code with it, so they match.
                context.ProtocolMessage.RedirectUri = Sso.RedirectUri(publicUrl, string.Empty);
            }
        };
        options.Events.OnRemoteFailure = context =>
        {
            var log = context.HttpContext.RequestServices.GetRequiredService<ILogger<SsoOptionsSetup>>();
            SsoLog.Failed(log, context.Failure, context.Failure?.Message ?? "unknown error");
            var cancelled = context.Failure?.Message.Contains("access_denied", StringComparison.OrdinalIgnoreCase) == true;
            context.Response.Redirect(cancelled ? "/account/login?sso=cancelled" : "/account/login?sso=failed");
            context.HandleResponse();
            return Task.CompletedTask;
        };
    }

    public void Configure(OpenIdConnectOptions options) => Configure(Options.DefaultName, options);
}

internal static partial class SsoLog
{
    [LoggerMessage(Level = LogLevel.Information, Message = "Signed in {Email} with single sign-on ({Label} account {Who})")]
    public static partial void SignedIn(ILogger logger, string? email, string label, string who);

    [LoggerMessage(Level = LogLevel.Information, Message = "Linked {Email} to {Label} account {Who}")]
    public static partial void Linked(ILogger logger, string? email, string label, string who);

    [LoggerMessage(Level = LogLevel.Information, Message = "Linked {Email} to {Label} account {Who} by its verified email")]
    public static partial void LinkedByEmail(ILogger logger, string? email, string label, string who);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Single sign-on by {Label} account {Who} ({Subject}): not linked to a DG SIEM account")]
    public static partial void NotLinked(ILogger logger, string label, string who, string subject);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Couldn't link {Who}: already linked to {Email}")]
    public static partial void LinkTaken(ILogger logger, string who, string? email);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Single sign-on for {Email} refused: {Reason}")]
    public static partial void Refused(ILogger logger, string? email, string reason);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Single sign-on failed: {Message}")]
    public static partial void Failed(ILogger logger, Exception? exception, string message);
}
