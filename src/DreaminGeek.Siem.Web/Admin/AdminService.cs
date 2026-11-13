using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using DreaminGeek.Siem.Core.Agents;
using DreaminGeek.Siem.Data;
using DreaminGeek.Siem.Data.Entities;
using DreaminGeek.Siem.Storage.ClickHouse;
using DreaminGeek.Siem.Web.Agents;
using DreaminGeek.Siem.Web.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace DreaminGeek.Siem.Web.Admin;

/// <summary>A rule the admin broke; the message is shown to them as-is.</summary>
public sealed class AdminException(string message) : Exception(message);

public sealed record TenantSummary(Guid Id, string Slug, string Name, int Agents, int Users, DateTimeOffset CreatedAt);
public sealed record UserSummary(Guid Id, string Email, string DisplayName, bool IsGlobalAdmin, bool Locked, IReadOnlyList<(string Tenant, TenantRole Role)> Grants, bool TwoFactor = false);
public sealed record DropRuleSummary(Guid Id, string Name, string? Tenant, string? Dataset, string? Field, string Match, string? Value, bool Enabled, long Dropped, DateTimeOffset? LastDropped);

/// <summary>
/// Administration shared by the admin pages and the CLI, so both enforce the same rules.
/// UI callers pass the caller's <see cref="UserAccess"/>; every method re-checks it's a global admin.
/// </summary>
public sealed class AdminService(
    IDbContextFactory<SiemDbContext> dbFactory,
    IServiceScopeFactory scopes,
    CertificateAuthority ca,
    TenantAccess access)
{
    private static readonly JsonSerializerOptions PrettyJson = new(AgentJsonContext.Default.Options) { WriteIndented = true };

    // ------------------------------------------------------------------ tenants

    public async Task<IReadOnlyList<TenantSummary>> ListTenantsAsync(UserAccess caller, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can do this.", ct);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        return await db.Tenants.OrderBy(t => t.Slug)
            .Select(t => new TenantSummary(t.Id, t.Slug, t.Name, t.Agents.Count, db.TenantMemberships.Count(m => m.TenantId == t.Id), t.CreatedAt))
            .ToListAsync(ct);
    }

    public async Task AddTenantAsync(UserAccess? caller, string slug, string name, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can do this.", ct);
        slug = (slug ?? string.Empty).Trim().ToLowerInvariant();
        name = (name ?? string.Empty).Trim();
        if (!TenantRowPolicies.IsValidSlug(slug))
        {
            throw new AdminException("Tenant IDs are 1-32 lowercase letters, digits or '-', starting with a letter or digit (e.g. acme, globex, dg).");
        }
        if (name.Length is 0 or > 200)
        {
            throw new AdminException("Enter a tenant name (up to 200 characters).");
        }
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        if (await db.Tenants.AnyAsync(t => t.Slug == slug, ct))
        {
            throw new AdminException($"Tenant '{slug}' already exists.");
        }
        db.Tenants.Add(new Tenant { Id = Guid.NewGuid(), Slug = slug, Name = name });
        await db.SaveChangesAsync(ct);
    }

    // ------------------------------------------------------------------ agents

    /// <summary>Creates a single-use enrollment token. Returns the token text (shown once).</summary>
    public async Task<string> CreateEnrollmentTokenAsync(UserAccess? caller, string tenantSlug, string? agentName, int hours, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can do this.", ct);
        if (hours is < 1 or > 24 * 30)
        {
            throw new AdminException("Tokens can be valid for 1 hour to 30 days.");
        }
        agentName = string.IsNullOrWhiteSpace(agentName) ? null : agentName.Trim();
        if (agentName is not null && (agentName.Length > 63 || !agentName.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_')))
        {
            throw new AdminException("Agent names are up to 63 letters, digits, '-', '.' or '_'.");
        }
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var wanted = tenantSlug?.ToLowerInvariant();
        var tenant = await db.Tenants.SingleOrDefaultAsync(t => t.Slug == wanted, ct)
            ?? throw new AdminException($"No tenant '{tenantSlug}'.");
        var token = EnrollmentTokenFormat.Create(ca.CaFingerprint, out var hash);
        db.EnrollmentTokens.Add(new EnrollmentToken
        {
            Id = Guid.NewGuid(),
            TenantId = tenant.Id,
            TokenHash = hash,
            AgentName = agentName,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(hours),
        });
        await db.SaveChangesAsync(ct);
        return token;
    }

    public async Task<string> GetAgentConfigJsonAsync(UserAccess caller, Guid agentId, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can do this.", ct);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var json = await db.Agents.Where(a => a.Id == agentId).Select(a => a.ConfigJson).SingleOrDefaultAsync(ct)
            ?? throw new AdminException("That agent no longer exists.");
        return JsonSerializer.Serialize(AgentRegistry.ParseConfig(json), PrettyJson);
    }

    /// <summary>Validates and saves an agent's input config; the agent picks it up on its next poll.</summary>
    public async Task SetAgentConfigAsync(UserAccess? caller, Guid agentId, string json, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can do this.", ct);
        var config = ParseAndValidateConfig(json);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var agent = await db.Agents.SingleOrDefaultAsync(a => a.Id == agentId, ct) ?? throw new AdminException("That agent no longer exists.");
        agent.ConfigJson = JsonSerializer.Serialize(config, AgentJsonContext.Default.AgentConfig);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>File inputs: absolute paths, wildcards only in the file name, a sane app name.</summary>
    private static void ValidateFileInput(InputConfig input)
    {
        if (input.Paths is not { Count: > 0 })
        {
            throw new AdminException("A File input needs \"paths\", e.g. [\"/var/log/nginx/access.log\"].");
        }
        foreach (var path in input.Paths)
        {
            var isAbsolute = path.StartsWith('/') || (path.Length > 2 && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] is '\\' or '/');
            if (!isAbsolute)
            {
                throw new AdminException($"File path '{path}' must be absolute (start with / or a drive letter).");
            }
            var slash = Math.Max(path.LastIndexOf('/'), path.LastIndexOf('\\'));
            if (path.AsSpan(0, Math.Max(slash, 0)).IndexOfAny('*', '?') >= 0)
            {
                throw new AdminException($"File path '{path}': wildcards (* ?) are only allowed in the file name, not in folders.");
            }
            if (slash == path.Length - 1)
            {
                throw new AdminException($"File path '{path}' is a folder; add a file name or pattern such as *.log.");
            }
        }
        if (input.Multiline == MultilineMode.Pattern)
        {
            if (string.IsNullOrWhiteSpace(input.MultilineStart))
            {
                throw new AdminException("\"multiline\": \"Pattern\" needs \"multilineStart\", a regular expression for an event's first line, e.g. \"^\\\\[\\\\d{4}-\".");
            }
            try
            {
                _ = new System.Text.RegularExpressions.Regex(input.MultilineStart, System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromMilliseconds(50));
            }
            catch (ArgumentException ex)
            {
                throw new AdminException($"\"multilineStart\" isn't a valid regular expression: {ex.Message}");
            }
        }
        if (input.App is { Length: > 48 } || input.App?.Any(c => c is <= ' ' or >= (char)127) == true)
        {
            throw new AdminException("\"app\" must be up to 48 characters with no spaces.");
        }
    }

    private static void ValidateEventLogInput(InputConfig input)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var channel in input.Channels ?? [])
        {
            if (string.IsNullOrWhiteSpace(channel.Name) || channel.Name.Length > 256 || channel.Name.Any(char.IsControl))
            {
                throw new AdminException("Each event log channel needs a \"name\", e.g. \"Security\" or \"Microsoft-Windows-Sysmon/Operational\".");
            }
            if (!names.Add(channel.Name.Trim()))
            {
                throw new AdminException($"Event log '{channel.Name}' is listed twice.");
            }
            if (channel.Query is { } query && (query.Length > 4096 || !query.TrimStart().StartsWith('*') && !query.TrimStart().StartsWith("<QueryList", StringComparison.OrdinalIgnoreCase)))
            {
                throw new AdminException($"The query for '{channel.Name}' should be an event-log XPath such as *[System[(EventID=4624)]].");
            }
        }
    }

    private static void ValidateHecInput(InputConfig input)
    {
        if (input.Tokens is not { Count: > 0 })
        {
            throw new AdminException("A Hec input needs at least one token in \"tokens\" (16 or more characters, e.g. a GUID).");
        }
        foreach (var token in input.Tokens)
        {
            if (token.Length < 16 || token.Length > 256 || token.Any(c => c is <= ' ' or >= (char)127))
            {
                throw new AdminException("HEC tokens must be 16 to 256 characters with no spaces; a GUID works well.");
            }
        }
        if (input.Tokens.Distinct(StringComparer.Ordinal).Count() != input.Tokens.Count)
        {
            throw new AdminException("A HEC token is listed twice.");
        }
    }

    public static AgentConfig ParseAndValidateConfig(string json)
    {
        AgentConfig? config;
        try
        {
            config = JsonSerializer.Deserialize(json, AgentJsonContext.Default.AgentConfig);
        }
        catch (JsonException ex)
        {
            throw new AdminException($"The config isn't valid JSON: {ex.Message}");
        }
        if (config is null)
        {
            throw new AdminException("The config is empty.");
        }
        foreach (var input in config.Inputs)
        {
            if (input.Type == InputType.File)
            {
                ValidateFileInput(input);
                continue;
            }
            if (input.Type == InputType.WindowsEventLog)
            {
                ValidateEventLogInput(input);
                continue;
            }
            if (input.Port is < 1 or > 65535)
            {
                throw new AdminException($"Input {input.Type} has an invalid port ({input.Port}).");
            }
            if (input.BindAddress is not ("0.0.0.0" or "::" or "*" or "") && !IPAddress.TryParse(input.BindAddress, out _))
            {
                throw new AdminException($"Input {input.Type} has an invalid bind address ({input.BindAddress}).");
            }
            if (input.Type == InputType.Hec)
            {
                ValidateHecInput(input);
            }
        }
        var duplicate = config.Inputs.Where(i => i.Type is not (InputType.File or InputType.WindowsEventLog))
            .GroupBy(i => (i.Type == InputType.SyslogUdp ? "udp" : "tcp", i.Port)).FirstOrDefault(g => g.Count() > 1);
        if (duplicate is not null)
        {
            throw new AdminException($"Two inputs use {duplicate.Key.Item1} port {duplicate.Key.Port}.");
        }
        foreach (var hint in config.SourceHints)
        {
            if (!IPNetwork.TryParse(hint.Source, out _) && !IPAddress.TryParse(hint.Source, out _))
            {
                throw new AdminException($"Source hint '{hint.Source}' isn't an IP address or CIDR range.");
            }
            if (string.IsNullOrWhiteSpace(hint.Dataset))
            {
                throw new AdminException($"Source hint '{hint.Source}' needs a dataset (e.g. unifi).");
            }
        }
        if (config.ConfigPollSeconds is < 10 or > 3600)
        {
            throw new AdminException("configPollSeconds must be between 10 and 3600.");
        }
        return config;
    }

    public async Task SetAgentRevokedAsync(UserAccess? caller, Guid agentId, bool revoked, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can do this.", ct);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var agent = await db.Agents.SingleOrDefaultAsync(a => a.Id == agentId, ct) ?? throw new AdminException("That agent no longer exists.");
        agent.RevokedAt = revoked ? DateTimeOffset.UtcNow : null;
        await db.SaveChangesAsync(ct);
    }

    public async Task DeleteAgentAsync(UserAccess? caller, Guid agentId, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can do this.", ct);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        await db.Agents.Where(a => a.Id == agentId).ExecuteDeleteAsync(ct);
    }

    // ------------------------------------------------------------------ users

    public async Task<IReadOnlyList<UserSummary>> ListUsersAsync(UserAccess caller, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can do this.", ct);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var users = await db.Users.Include(u => u.Memberships).ThenInclude(m => m.Tenant).OrderBy(u => u.Email).ToListAsync(ct);
        var now = DateTimeOffset.UtcNow;
        return users.Select(u => new UserSummary(u.Id, u.Email ?? string.Empty, u.DisplayName, u.IsGlobalAdmin, u.LockoutEnd > now,
            u.Memberships.OrderBy(m => m.Tenant.Slug).Select(m => (m.Tenant.Slug, m.Role)).ToList(), u.TwoFactorEnabled)).ToList();
    }

    /// <summary>Creates a user with a generated password, which is returned (shown once).</summary>
    public async Task<string> AddUserAsync(UserAccess? caller, string email, string? displayName, bool globalAdmin, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can do this.", ct);
        email = (email ?? string.Empty).Trim();
        await using var scope = scopes.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<SiemUser>>();
        var user = new SiemUser
        {
            Id = Guid.NewGuid(),
            UserName = email,
            Email = email,
            EmailConfirmed = true,
            DisplayName = string.IsNullOrWhiteSpace(displayName) ? email : displayName.Trim(),
            IsGlobalAdmin = globalAdmin,
        };
        var password = Passwords.Generate();
        Check(await users.CreateAsync(user, password));
        return password;
    }

    /// <summary>Sets a new generated password, clears lockout and signs out the user's sessions. Returns the password.</summary>
    public async Task<string> ResetPasswordAsync(UserAccess? caller, Guid userId, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can do this.", ct);
        await using var scope = scopes.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<SiemUser>>();
        var user = await users.FindByIdAsync(userId.ToString()) ?? throw new AdminException("That user no longer exists.");
        var password = Passwords.Generate();
        Check(await users.RemovePasswordAsync(user));
        Check(await users.AddPasswordAsync(user, password));
        await users.SetLockoutEndDateAsync(user, null);
        await users.ResetAccessFailedCountAsync(user);
        await users.UpdateSecurityStampAsync(user);
        return password;
    }

    /// <summary>
    /// Turns off a user's two-factor (lost phone): clears the authenticator key and recovery codes and signs
    /// them out everywhere. They sign in with just their password and set it up again.
    /// </summary>
    public async Task ResetTwoFactorAsync(UserAccess? caller, Guid userId, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can do this.", ct);
        await using var scope = scopes.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<SiemUser>>();
        var user = await users.FindByIdAsync(userId.ToString()) ?? throw new AdminException("That user no longer exists.");
        await ResetTwoFactorAsync(users, user);
    }

    internal static async Task ResetTwoFactorAsync(UserManager<SiemUser> users, SiemUser user)
    {
        Check(await users.SetTwoFactorEnabledAsync(user, false));
        Check(await users.ResetAuthenticatorKeyAsync(user));
        await users.GenerateNewTwoFactorRecoveryCodesAsync(user, 0);
        await users.SetLockoutEndDateAsync(user, null);
        await users.ResetAccessFailedCountAsync(user);
        await users.UpdateSecurityStampAsync(user);
    }

    public async Task UnlockAsync(UserAccess? caller, Guid userId, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can do this.", ct);
        await using var scope = scopes.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<SiemUser>>();
        var user = await users.FindByIdAsync(userId.ToString()) ?? throw new AdminException("That user no longer exists.");
        await users.SetLockoutEndDateAsync(user, null);
        await users.ResetAccessFailedCountAsync(user);
        access.Forget(userId);
    }

    public async Task SetGlobalAdminAsync(UserAccess caller, Guid userId, bool admin, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can do this.", ct);
        if (userId == caller.UserId && !admin)
        {
            throw new AdminException("You can't remove your own admin rights; ask another admin.");
        }
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var user = await db.Users.SingleOrDefaultAsync(u => u.Id == userId, ct) ?? throw new AdminException("That user no longer exists.");
        user.IsGlobalAdmin = admin;
        await db.SaveChangesAsync(ct);
        if (!admin)
        {
            await SignOutEverywhereAsync(userId);
        }
        access.Forget(userId);
    }

    public async Task GrantAsync(UserAccess? caller, Guid userId, string tenantSlug, TenantRole role, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can do this.", ct);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var tenant = await db.Tenants.SingleOrDefaultAsync(t => t.Slug == tenantSlug, ct) ?? throw new AdminException($"No tenant '{tenantSlug}'.");
        if (!await db.Users.AnyAsync(u => u.Id == userId, ct))
        {
            throw new AdminException("That user no longer exists.");
        }
        var membership = await db.TenantMemberships.SingleOrDefaultAsync(m => m.UserId == userId && m.TenantId == tenant.Id, ct);
        if (membership is null)
        {
            db.TenantMemberships.Add(new TenantMembership { UserId = userId, TenantId = tenant.Id, Role = role });
        }
        else
        {
            membership.Role = role;
        }
        await db.SaveChangesAsync(ct);
        if (membership is not null)
        {
            await SignOutEverywhereAsync(userId); // a changed role can be a demotion
        }
        access.Forget(userId);
    }

    public async Task RevokeAsync(UserAccess? caller, Guid userId, string tenantSlug, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can do this.", ct);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        await db.TenantMemberships.Where(m => m.UserId == userId && m.Tenant.Slug == tenantSlug).ExecuteDeleteAsync(ct);
        await SignOutEverywhereAsync(userId);
        access.Forget(userId);
    }

    public async Task DeleteUserAsync(UserAccess caller, Guid userId, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can do this.", ct);
        if (userId == caller.UserId)
        {
            throw new AdminException("You can't delete your own account.");
        }
        await using var scope = scopes.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<SiemUser>>();
        var user = await users.FindByIdAsync(userId.ToString()) ?? throw new AdminException("That user no longer exists.");
        Check(await users.DeleteAsync(user));
        access.Forget(userId);
    }

    // ------------------------------------------------------------------ drop rules

    public async Task<IReadOnlyList<DropRuleSummary>> ListDropRulesAsync(UserAccess caller, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can do this.", ct);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        return await db.DropRules.OrderBy(r => r.CreatedAt)
            .Select(r => new DropRuleSummary(r.Id, r.Name, r.Tenant == null ? null : r.Tenant.Slug, r.Dataset, r.Field, r.Match, r.Value, r.Enabled, r.DroppedTotal, r.LastDroppedAt))
            .ToListAsync(ct);
    }

    /// <summary>
    /// Adds a drop rule. <paramref name="match"/> is any | equals | contains | startswith | regex;
    /// a field needs a condition and vice versa, and a rule must name a dataset and/or a field.
    /// </summary>
    public async Task AddDropRuleAsync(UserAccess? caller, string name, string? tenantSlug, string? dataset, string? field, string match, string? value, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can do this.", ct);
        name = (name ?? string.Empty).Trim();
        dataset = string.IsNullOrWhiteSpace(dataset) ? null : dataset.Trim();
        field = string.IsNullOrWhiteSpace(field) ? null : field.Trim();
        match = (match ?? "any").Trim().ToLowerInvariant();
        if (name.Length is 0 or > 200)
        {
            throw new AdminException("Give the rule a name, e.g. \"UniFi IPsec keepalives\".");
        }
        if (match is not ("any" or "equals" or "contains" or "startswith" or "regex"))
        {
            throw new AdminException("Match must be any, equals, contains, startswith or regex.");
        }
        if ((field is null) != (match == "any"))
        {
            throw new AdminException(field is null ? "A condition needs a field to test." : "A field needs a condition (equals, contains, starts with or regex).");
        }
        if (dataset is null && field is null)
        {
            throw new AdminException("A rule needs a dataset and/or a field condition; it can't drop everything.");
        }
        if (match == "regex")
        {
            try
            {
                _ = new System.Text.RegularExpressions.Regex(value ?? string.Empty, System.Text.RegularExpressions.RegexOptions.NonBacktracking);
            }
            catch (ArgumentException ex)
            {
                throw new AdminException($"The regular expression isn't valid: {ex.Message}");
            }
        }

        await using var db = await dbFactory.CreateDbContextAsync(ct);
        Guid? tenantId = null;
        if (!string.IsNullOrWhiteSpace(tenantSlug))
        {
            var slug = tenantSlug.Trim().ToLowerInvariant();
            tenantId = (await db.Tenants.SingleOrDefaultAsync(t => t.Slug == slug, ct))?.Id ?? throw new AdminException($"No tenant '{tenantSlug}'.");
        }
        db.DropRules.Add(new DropRuleEntity
        {
            Id = Guid.NewGuid(),
            Name = name,
            TenantId = tenantId,
            Dataset = dataset,
            Field = field,
            Match = match,
            Value = match == "any" ? null : value ?? string.Empty,
        });
        await db.SaveChangesAsync(ct);
    }

    public async Task SetDropRuleEnabledAsync(UserAccess? caller, Guid id, bool enabled, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can do this.", ct);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        await db.DropRules.Where(r => r.Id == id).ExecuteUpdateAsync(s => s.SetProperty(r => r.Enabled, enabled), ct);
    }

    public async Task DeleteDropRuleAsync(UserAccess? caller, Guid id, CancellationToken ct)
    {
        await access.RequireGlobalAdminAsync(caller, "Only global admins can do this.", ct);
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        await db.DropRules.Where(r => r.Id == id).ExecuteDeleteAsync(ct);
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>
    /// Changes the user's security stamp: their browsers are signed out within a minute (open tabs too),
    /// so they can't keep rights they just lost. Signing in again picks up the new access.
    /// </summary>
    private async Task SignOutEverywhereAsync(Guid userId)
    {
        await using var scope = scopes.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<SiemUser>>();
        if (await users.FindByIdAsync(userId.ToString()) is { } user)
        {
            await users.UpdateSecurityStampAsync(user);
        }
    }

    /// <summary>Null caller = the server CLI (shell access already implies full control).</summary>
    private static void Require(UserAccess caller)
    {
        if (caller is not null && !caller.IsGlobalAdmin)
        {
            throw new AdminException("Only global admins can do this.");
        }
    }

    private static void Check(IdentityResult result)
    {
        if (!result.Succeeded)
        {
            throw new AdminException(string.Join(" ", result.Errors.Select(e => e.Description)));
        }
    }
}

/// <summary>Generated passwords: 20 characters with every class Identity requires, no look-alikes.</summary>
public static class Passwords
{
    public static string Generate()
    {
        const string lower = "abcdefghijkmnpqrstuvwxyz", upper = "ABCDEFGHJKLMNPQRSTUVWXYZ", digits = "23456789", symbols = "!@#$%^&*-_=+";
        const string all = lower + upper + digits + symbols;
        var chars = new char[20];
        chars[0] = lower[RandomNumberGenerator.GetInt32(lower.Length)];
        chars[1] = upper[RandomNumberGenerator.GetInt32(upper.Length)];
        chars[2] = digits[RandomNumberGenerator.GetInt32(digits.Length)];
        chars[3] = symbols[RandomNumberGenerator.GetInt32(symbols.Length)];
        for (var i = 4; i < chars.Length; i++)
        {
            chars[i] = all[RandomNumberGenerator.GetInt32(all.Length)];
        }
        RandomNumberGenerator.Shuffle(chars.AsSpan());
        return new string(chars);
    }
}
