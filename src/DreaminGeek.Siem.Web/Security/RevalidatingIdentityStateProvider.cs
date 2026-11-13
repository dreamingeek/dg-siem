using System.Security.Claims;
using DreaminGeek.Siem.Data.Entities;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace DreaminGeek.Siem.Web.Security;

/// <summary>
/// Re-checks the signed-in account of every open tab each minute. If the user was deleted, locked out,
/// or their access changed (admins update the security stamp when they do that), the tab is signed out
/// instead of keeping the rights it had when it opened.
/// </summary>
public sealed class RevalidatingIdentityStateProvider(
    ILoggerFactory loggerFactory,
    IServiceScopeFactory scopes,
    IOptions<IdentityOptions> identityOptions)
    : RevalidatingServerAuthenticationStateProvider(loggerFactory)
{
    /// <summary>Also the cookie's security stamp check interval, so new requests agree with open tabs.</summary>
    public static readonly TimeSpan Interval = TimeSpan.FromMinutes(1);

    protected override TimeSpan RevalidationInterval => Interval;

    protected override async Task<bool> ValidateAuthenticationStateAsync(AuthenticationState authenticationState, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authenticationState);
        await using var scope = scopes.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<SiemUser>>();
        var principal = authenticationState.User;
        var user = await users.GetUserAsync(principal);
        if (user is null || await users.IsLockedOutAsync(user))
        {
            return false;
        }
        if (!users.SupportsUserSecurityStamp)
        {
            return true;
        }
        var claimed = principal.FindFirstValue(identityOptions.Value.ClaimsIdentity.SecurityStampClaimType);
        return string.Equals(claimed, await users.GetSecurityStampAsync(user), StringComparison.Ordinal);
    }
}
