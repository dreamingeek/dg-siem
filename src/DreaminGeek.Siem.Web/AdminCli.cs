using System.Globalization;
using System.Text.Json;
using DreaminGeek.Siem.Core.Agents;
using DreaminGeek.Siem.Data;
using DreaminGeek.Siem.Data.Entities;
using DreaminGeek.Siem.Web.Agents;
using DreaminGeek.Siem.Web.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace DreaminGeek.Siem.Web;

/// <summary>
/// Admin commands until the admin UI exists, e.g.
/// <c>docker compose exec dg-siem-server dg-siem-server token create acme --name acme-log-col</c>.
/// </summary>
public static class AdminCli
{
    private const string Usage = """
        dg-siem-server admin commands:
          tenant add <slug> <name...>
          tenant list
          token create <tenant> [--name <agent-name>] [--hours <n>]   (default 24h, single use)
          agent list
          agent revoke <tenant>/<agent>
          agent config get <tenant>/<agent>
          agent config set <tenant>/<agent> <file.json | ->
          drop list
          drop add --name <text> [--tenant <slug>] [--dataset <ds|prefix*>]
                   [--field <ecs.field> (--equals|--contains|--startswith|--regex) <value>]
          drop enable|disable|remove <id-prefix>
          user add <email> [--admin] [--name <display name>]   (prints a generated password)
          user list
          user passwd <email>                                  (new generated password, clears lockout)
          user 2fa-reset <email>                               (turn off two-factor, e.g. a lost phone)
          user 2fa-required on|off                             (require two-factor for everyone)
          user grant <email> <tenant> [viewer|admin]
          user revoke <email> <tenant>
          user admin <email> on|off                            (global admin: sees every tenant)
          user remove <email>
          backup now                                           (config + events, as the nightly backup)
          backup list
          backup restore <config.dgsb> [--events <events-....zip>]
                   (stop the server first; events only into an empty events table, see docs/backups.md)
        """;

    private static readonly string[] DropConditions = ["equals", "contains", "startswith", "regex"];

    private static readonly JsonSerializerOptions Pretty = new(AgentJsonContext.Default.Options) { WriteIndented = true };

    public static bool IsCommand(string[] args) =>
        args.Length > 0 && args[0] is "tenant" or "token" or "agent" or "drop" or "user" or "backup" or "help" or "--help";

    public static async Task<int> RunAsync(IServiceProvider services, string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SiemDbContext>();
        var ca = scope.ServiceProvider.GetRequiredService<CertificateAuthority>();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<SiemUser>>();
        var admin = scope.ServiceProvider.GetRequiredService<DreaminGeek.Siem.Web.Admin.AdminService>();

        try
        {
            switch (args)
            {
                case ["tenant", "add", var slug, .. var nameParts] when nameParts.Length > 0:
                    await admin.AddTenantAsync(UserAccess.Shell, slug, string.Join(' ', nameParts), CancellationToken.None);
                    Console.WriteLine($"Tenant '{slug.ToLowerInvariant()}' added.");
                    return 0;

                case ["tenant", "list"]:
                    foreach (var t in await db.Tenants.OrderBy(t => t.Slug).ToListAsync())
                    {
                        Console.WriteLine($"{t.Slug,-12} {t.Name}  (retention {t.RetentionDays}d)");
                    }
                    return 0;

                case ["token", "create", var slug, .. var rest]:
                {
                    var name = Option(rest, "--name");
                    var hours = int.Parse(Option(rest, "--hours") ?? "24", CultureInfo.InvariantCulture);
                    Console.WriteLine(await admin.CreateEnrollmentTokenAsync(UserAccess.Shell, slug, name, hours, CancellationToken.None));
                    Console.Error.WriteLine($"Single-use token for tenant '{slug}'{(name is null ? "" : $", agent '{name}'")}, expires in {hours}h.");
                    return 0;
                }

                case ["agent", "list"]:
                    foreach (var a in await db.Agents.Include(a => a.Tenant).OrderBy(a => a.Tenant.Slug).ThenBy(a => a.Name).ToListAsync())
                    {
                        var state = a.RevokedAt is not null ? "REVOKED" : $"seen {a.LastSeenAt:u}";
                        Console.WriteLine($"{a.Tenant.Slug}/{a.Name,-20} v{a.Version,-8} cert until {a.CertificateNotAfter:yyyy-MM-dd}  {state}");
                    }
                    return 0;

                case ["agent", "revoke", var path]:
                {
                    var agent = await FindAgentAsync(db, path);
                    agent.RevokedAt = DateTimeOffset.UtcNow;
                    await db.SaveChangesAsync();
                    Console.WriteLine($"Revoked {path}. It is rejected within 30 seconds.");
                    return 0;
                }

                case ["agent", "config", "get", var path]:
                {
                    var agent = await FindAgentAsync(db, path);
                    Console.WriteLine(JsonSerializer.Serialize(AgentRegistry.ParseConfig(agent.ConfigJson), Pretty));
                    return 0;
                }

                case ["agent", "config", "set", var path, var file]:
                {
                    var agent = await FindAgentAsync(db, path);
                    var json = file == "-" ? await Console.In.ReadToEndAsync() : await File.ReadAllTextAsync(file);
                    var config = DreaminGeek.Siem.Web.Admin.AdminService.ParseAndValidateConfig(json);
                    agent.ConfigJson = JsonSerializer.Serialize(config, AgentJsonContext.Default.AgentConfig);
                    await db.SaveChangesAsync();
                    Console.WriteLine($"Config saved. {path} picks it up within {config.ConfigPollSeconds}s.");
                    return 0;
                }

                case ["drop", "list"]:
                    foreach (var r in await db.DropRules.Include(r => r.Tenant).OrderBy(r => r.CreatedAt).ToListAsync())
                    {
                        var condition = r.Field is null ? "(all)" : $"{r.Field} {r.Match} \"{r.Value}\"";
                        Console.WriteLine($"{r.Id.ToString()[..8]}  {(r.Enabled ? "on " : "off")}  {r.Tenant?.Slug ?? "*",-6} {r.Dataset ?? "*",-18} {condition,-45} dropped {r.DroppedTotal,10:N0}  {r.Name}");
                    }
                    return 0;

                case ["drop", "add", .. var rest]:
                {
                    var conditions = DropConditions
                        .Select(m => (Match: m, Value: Option(rest, "--" + m))).Where(c => c.Value is not null).ToList();
                    if (conditions.Count > 1)
                    {
                        throw new InvalidOperationException("Use only one of --equals, --contains, --startswith, --regex.");
                    }
                    await admin.AddDropRuleAsync(UserAccess.Shell, Option(rest, "--name") ?? throw new InvalidOperationException("--name is required."),
                        Option(rest, "--tenant"), Option(rest, "--dataset"), Option(rest, "--field"),
                        conditions.Count == 0 ? "any" : conditions[0].Match, conditions.Count == 0 ? null : conditions[0].Value, CancellationToken.None);
                    Console.WriteLine("Added drop rule. Active within 30s.");
                    return 0;
                }

                case ["drop", var verb and ("enable" or "disable" or "remove"), var idPrefix]:
                {
                    var matches = (await db.DropRules.ToListAsync()).Where(r => r.Id.ToString().StartsWith(idPrefix, StringComparison.OrdinalIgnoreCase)).ToList();
                    if (matches.Count != 1)
                    {
                        throw new InvalidOperationException(matches.Count == 0 ? $"No rule '{idPrefix}'." : $"'{idPrefix}' matches {matches.Count} rules; use more characters.");
                    }
                    if (verb == "remove")
                    {
                        db.DropRules.Remove(matches[0]);
                    }
                    else
                    {
                        matches[0].Enabled = verb == "enable";
                    }
                    await db.SaveChangesAsync();
                    Console.WriteLine($"Rule {idPrefix} {verb}d. Takes effect within 30s.");
                    return 0;
                }

                case ["user", "add", var email, .. var rest]:
                {
                    var user = new SiemUser
                    {
                        Id = Guid.NewGuid(),
                        UserName = email.Trim(),
                        Email = email.Trim(),
                        EmailConfirmed = true,
                        DisplayName = Option(rest, "--name") ?? email.Trim(),
                        IsGlobalAdmin = rest.Contains("--admin"),
                    };
                    var password = DreaminGeek.Siem.Web.Admin.Passwords.Generate();
                    Check(await users.CreateAsync(user, password));
                    Console.WriteLine($"User {user.Email} created{(user.IsGlobalAdmin ? " (global admin)" : "")}.");
                    Console.WriteLine($"Password: {password}");
                    if (!user.IsGlobalAdmin)
                    {
                        Console.WriteLine($"Grant tenants with: user grant {user.Email} <tenant>");
                    }
                    return 0;
                }

                case ["user", "list"]:
                    foreach (var u in await db.Users.Include(u => u.Memberships).ThenInclude(m => m.Tenant).OrderBy(u => u.Email).ToListAsync())
                    {
                        var scopeText = u.IsGlobalAdmin ? "global admin" : string.Join(", ", u.Memberships.Select(m => $"{m.Tenant.Slug}:{m.Role.ToString().ToLowerInvariant()}"));
                        var locked = u.LockoutEnd > DateTimeOffset.UtcNow ? "  LOCKED" : "";
                        var twoFactor = u.TwoFactorEnabled ? "  2FA" : "";
                        Console.WriteLine($"{u.Email,-32} {scopeText}{twoFactor}{locked}");
                    }
                    return 0;

                case ["user", "2fa-reset", var email]:
                {
                    var user = await FindUserAsync(users, email);
                    await DreaminGeek.Siem.Web.Admin.AdminService.ResetTwoFactorAsync(users, user);
                    Console.WriteLine($"Two-factor turned off for {user.Email}; they can sign in with their password and set it up again.");
                    return 0;
                }

                case ["user", "2fa-required", var onOff and ("on" or "off")]:
                {
                    // Edits the same setting as Administration → Users, without needing the settings service.
                    var row = await db.AppSettings.FirstOrDefaultAsync(x => x.Key == "general");
                    var json = System.Text.Json.Nodes.JsonNode.Parse(row?.Value ?? "{}")!.AsObject();
                    json["timeZone"] ??= "UTC";
                    json["requireTwoFactor"] = onOff == "on";
                    if (row is null)
                    {
                        db.AppSettings.Add(new DreaminGeek.Siem.Data.Entities.AppSetting { Key = "general", Value = json.ToJsonString() });
                    }
                    else
                    {
                        row.Value = json.ToJsonString();
                        row.UpdatedAt = DateTimeOffset.UtcNow;
                    }
                    await db.SaveChangesAsync();
                    Console.WriteLine($"Two-factor is now {(onOff == "on" ? "required" : "optional")} for everyone (takes effect within 30 seconds).");
                    return 0;
                }

                case ["user", "passwd", var email]:
                {
                    var user = await FindUserAsync(users, email);
                    var password = DreaminGeek.Siem.Web.Admin.Passwords.Generate();
                    Check(await users.RemovePasswordAsync(user));
                    Check(await users.AddPasswordAsync(user, password));
                    await users.SetLockoutEndDateAsync(user, null);
                    await users.ResetAccessFailedCountAsync(user);
                    await users.UpdateSecurityStampAsync(user); // signs out existing sessions
                    Console.WriteLine($"New password for {user.Email}: {password}");
                    return 0;
                }

                case ["user", "grant", var email, var slug, .. var rest]:
                {
                    var user = await FindUserAsync(users, email);
                    var tenant = await db.Tenants.SingleOrDefaultAsync(t => t.Slug == slug) ?? throw new InvalidOperationException($"No tenant '{slug}'.");
                    var role = rest is ["admin"] ? TenantRole.Admin : rest is [] or ["viewer"] ? TenantRole.Viewer
                        : throw new InvalidOperationException("Role must be viewer or admin.");
                    var membership = await db.TenantMemberships.SingleOrDefaultAsync(m => m.UserId == user.Id && m.TenantId == tenant.Id);
                    if (membership is null)
                    {
                        db.TenantMemberships.Add(new TenantMembership { UserId = user.Id, TenantId = tenant.Id, Role = role });
                    }
                    else
                    {
                        membership.Role = role;
                    }
                    await db.SaveChangesAsync();
                    if (membership is not null)
                    {
                        await users.UpdateSecurityStampAsync(user); // a changed role can be a demotion
                    }
                    Console.WriteLine($"{user.Email} is {role.ToString().ToLowerInvariant()} of '{slug}'. Takes effect within a minute.");
                    return 0;
                }

                case ["user", "revoke", var email, var slug]:
                {
                    var user = await FindUserAsync(users, email);
                    var removed = await db.TenantMemberships.Where(m => m.UserId == user.Id && m.Tenant.Slug == slug).ExecuteDeleteAsync();
                    if (removed > 0)
                    {
                        await users.UpdateSecurityStampAsync(user); // signs out open sessions, which held the old access
                    }
                    Console.WriteLine(removed == 0 ? $"{user.Email} had no access to '{slug}'." : $"Revoked {user.Email} from '{slug}'. Their sessions are signed out within a minute.");
                    return 0;
                }

                case ["user", "admin", var email, var flag and ("on" or "off")]:
                {
                    var user = await FindUserAsync(users, email);
                    user.IsGlobalAdmin = flag == "on";
                    Check(await users.UpdateAsync(user));
                    if (flag == "off")
                    {
                        await users.UpdateSecurityStampAsync(user); // signs out open sessions, which held admin rights
                    }
                    Console.WriteLine($"{user.Email} global admin: {flag}. Takes effect within a minute.");
                    return 0;
                }

                case ["user", "remove", var email]:
                {
                    var user = await FindUserAsync(users, email);
                    Check(await users.DeleteAsync(user));
                    Console.WriteLine($"Removed {user.Email}.");
                    return 0;
                }

                case ["backup", "now"]:
                {
                    var backups = scope.ServiceProvider.GetRequiredService<DreaminGeek.Siem.Web.Backups.BackupService>();
                    var run = await backups.RunAsync(manual: true, CancellationToken.None);
                    Console.WriteLine($"Config: {run.ConfigFile ?? "-"} ({run.ConfigBytes:N0} bytes)");
                    Console.WriteLine($"Events: {(run.Events is null ? "-" : $"{run.Events.Name} ({run.Events.Bytes:N0} bytes)")}");
                    if (run.Error is not null)
                    {
                        Console.Error.WriteLine($"error: {run.Error}");
                        return 1;
                    }
                    return 0;
                }

                case ["backup", "list"]:
                {
                    var backups = scope.ServiceProvider.GetRequiredService<DreaminGeek.Siem.Web.Backups.BackupService>();
                    Console.WriteLine($"Config backups in {backups.Options.ConfigDirectory}:");
                    foreach (var f in backups.ListConfigBackups())
                    {
                        Console.WriteLine($"  {f.Name,-36} {f.Length,14:N0} bytes  {f.LastWriteTimeUtc:u}");
                    }
                    Console.WriteLine($"Event backups in {backups.Options.EventsDirectory}:");
                    foreach (var b in (await backups.GetStateAsync(CancellationToken.None)).EventBackups)
                    {
                        Console.WriteLine($"  {b.Name,-36} {b.Bytes,14:N0} bytes  {b.At:u}{(b.Base is null ? "" : $"  (needs {b.Base})")}");
                    }
                    return 0;
                }

                case ["backup", "restore", var file, .. var rest]:
                {
                    var backups = scope.ServiceProvider.GetRequiredService<DreaminGeek.Siem.Web.Backups.BackupService>();
                    await backups.RestoreAsync(file, Option(rest, "--events"), Console.Out, CancellationToken.None);
                    return 0;
                }

                default:
                    Console.Error.WriteLine(Usage);
                    return args is ["help"] or ["--help"] ? 0 : 2;
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or JsonException or FormatException or IOException or DbUpdateException or ArgumentException or DreaminGeek.Siem.Web.Admin.AdminException or DreaminGeek.Siem.Web.Backups.BackupException or Npgsql.NpgsqlException)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    private static async Task<SiemUser> FindUserAsync(UserManager<SiemUser> users, string email) =>
        await users.FindByEmailAsync(email.Trim()) ?? throw new InvalidOperationException($"No user '{email}'.");

    private static void Check(IdentityResult result)
    {
        if (!result.Succeeded)
        {
            throw new InvalidOperationException(string.Join(" ", result.Errors.Select(e => e.Description)));
        }
    }

    private static string? Option(string[] args, string name)
    {
        var i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    private static async Task<CollectorAgent> FindAgentAsync(SiemDbContext db, string path)
    {
        var parts = path.Split('/', 2);
        if (parts.Length != 2)
        {
            throw new InvalidOperationException("Use <tenant>/<agent>, e.g. acme/acme-log-col.");
        }
        return await db.Agents.SingleOrDefaultAsync(a => a.Tenant.Slug == parts[0] && a.Name == parts[1])
            ?? throw new InvalidOperationException($"No agent '{path}'.");
    }
}
