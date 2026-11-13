using System.Text;
using DreaminGeek.Siem.Alerting;
using DreaminGeek.Siem.Data.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.Memory;
using QRCoder;

namespace DreaminGeek.Siem.Web.Security;

/// <summary>Authenticator-app (TOTP) helpers: the otpauth link, its QR code, and the readable key.</summary>
public static class TwoFactor
{
    public const string Issuer = "DG SIEM";
    public const int RecoveryCodeCount = 10;

    /// <summary>The <c>otpauth://</c> link authenticator apps read from the QR code (6 digits, 30 s, SHA-1).</summary>
    public static string OtpAuthUri(string account, string key) =>
        $"otpauth://totp/{Uri.EscapeDataString(Issuer)}:{Uri.EscapeDataString(account)}" +
        $"?secret={key}&issuer={Uri.EscapeDataString(Issuer)}&digits=6";

    /// <summary>The key in groups of four for typing by hand: <c>ABCD EFGH …</c>.</summary>
    public static string FormatKey(string key)
    {
        ArgumentNullException.ThrowIfNull(key);
        var text = new StringBuilder();
        for (var i = 0; i < key.Length; i++)
        {
            if (i > 0 && i % 4 == 0)
            {
                text.Append(' ');
            }
            text.Append(char.ToUpperInvariant(key[i]));
        }
        return text.ToString();
    }

    /// <summary>QR code as inline SVG, dark modules on white (scanners need the contrast in either theme).</summary>
    public static string QrSvg(string text)
    {
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(text, QRCodeGenerator.ECCLevel.M);
        return new SvgQRCode(data).GetGraphic(5, "#0f1722", "#ffffff", drawQuietZones: true);
    }

    /// <summary>Authenticator codes as typed: spaces and dashes removed.</summary>
    public static string CleanCode(string? code) =>
        new((code ?? string.Empty).Where(c => !char.IsWhiteSpace(c) && c != '-').ToArray());

    /// <summary>
    /// Recovery codes as Identity issues them (<c>XXXXX-XXXXX</c>, upper case): spaces removed, upper-cased,
    /// and the dash put back if it was left out.
    /// </summary>
    public static string CleanRecoveryCode(string? code)
    {
        var text = new string((code ?? string.Empty).Where(c => !char.IsWhiteSpace(c)).ToArray()).ToUpperInvariant();
        return text.Length == 10 && !text.Contains('-', StringComparison.Ordinal) ? $"{text[..5]}-{text[5..]}" : text;
    }

    /// <summary>
    /// Pages a signed-in user without two-factor can still reach when it's required: the sign-in and
    /// account pages (to set it up), sign-out, the framework and static files.
    /// </summary>
    public static bool AllowedWithoutTwoFactor(PathString path) =>
        path.StartsWithSegments("/account") || path.StartsWithSegments("/_framework") || path.StartsWithSegments("/_blazor")
        || path.StartsWithSegments("/_content") || path.StartsWithSegments("/lib") || path.StartsWithSegments("/js")
        || path.StartsWithSegments("/fonts") || path.Value?.EndsWith(".css", StringComparison.OrdinalIgnoreCase) == true
        || path.Value?.EndsWith(".png", StringComparison.OrdinalIgnoreCase) == true
        || path.Value?.EndsWith(".ico", StringComparison.OrdinalIgnoreCase) == true;
}

/// <summary>
/// When <see cref="GeneralSettings.RequireTwoFactor"/> is on, sends signed-in users who haven't set up an
/// authenticator to the account page until they do (APIs get 403). Results are cached briefly per user.
/// </summary>
public sealed class TwoFactorPolicy(SettingsStore settings, IMemoryCache cache)
{
    private static readonly TimeSpan CacheFor = TimeSpan.FromSeconds(30);
    public const string SetupPath = "/account/security";

    public async Task<bool> IsSatisfiedAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var general = await cache.GetOrCreateAsync("2fa:policy", async e =>
        {
            e.AbsoluteExpirationRelativeToNow = CacheFor;
            return await settings.GetGeneralAsync(context.RequestAborted);
        });
        if (general?.RequireTwoFactor != true)
        {
            return true;
        }
        var id = context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (id is null)
        {
            return true;
        }
        return await cache.GetOrCreateAsync($"2fa:user:{id}", async e =>
        {
            e.AbsoluteExpirationRelativeToNow = CacheFor;
            var users = context.RequestServices.GetRequiredService<UserManager<SiemUser>>();
            var user = await users.FindByIdAsync(id);
            return user is null || await users.GetTwoFactorEnabledAsync(user);
        });
    }

    /// <summary>Call after a user's two-factor setting or the policy changes.</summary>
    public void Forget(Guid? userId = null)
    {
        cache.Remove("2fa:policy");
        if (userId is { } id)
        {
            cache.Remove($"2fa:user:{id}");
        }
    }
}

/// <summary>Where to go after signing in: only local paths, never another site.</summary>
public static class ReturnUrls
{
    public static string Safe(string? returnUrl) =>
        string.IsNullOrEmpty(returnUrl) || !Uri.IsWellFormedUriString(returnUrl, UriKind.Relative)
            || returnUrl.StartsWith("//", StringComparison.Ordinal) || returnUrl.StartsWith("/\\", StringComparison.Ordinal)
            || !returnUrl.StartsWith('/')
            ? "/search" : returnUrl;

    public static string Query(string? returnUrl) =>
        string.IsNullOrEmpty(returnUrl) ? string.Empty : $"?ReturnUrl={Uri.EscapeDataString(Safe(returnUrl))}";
}
