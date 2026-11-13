using DreaminGeek.Siem.Data.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace DreaminGeek.Siem.Data;

/// <summary>Metadata store (PostgreSQL). Event data lives in ClickHouse, never here.</summary>
public sealed class SiemDbContext(DbContextOptions<SiemDbContext> options)
    : IdentityDbContext<SiemUser, IdentityRole<Guid>, Guid>(options)
{
    public DbSet<Tenant> Tenants => Set<Tenant>();
    public DbSet<TenantMembership> TenantMemberships => Set<TenantMembership>();
    public DbSet<CollectorAgent> Agents => Set<CollectorAgent>();
    public DbSet<EnrollmentToken> EnrollmentTokens => Set<EnrollmentToken>();
    public DbSet<SavedSearch> SavedSearches => Set<SavedSearch>();
    public DbSet<Dashboard> Dashboards => Set<Dashboard>();
    public DbSet<AlertRule> AlertRules => Set<AlertRule>();
    public DbSet<AlertFiring> AlertFirings => Set<AlertFiring>();
    public DbSet<AppSetting> AppSettings => Set<AppSetting>();
    public DbSet<DropRuleEntity> DropRules => Set<DropRuleEntity>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        base.OnModelCreating(builder);

        builder.Entity<Tenant>(e =>
        {
            e.HasIndex(t => t.Slug).IsUnique();
            e.Property(t => t.Slug).HasMaxLength(32);
            e.Property(t => t.Name).HasMaxLength(200);
        });

        builder.Entity<TenantMembership>(e =>
        {
            e.HasKey(m => new { m.UserId, m.TenantId });
            e.HasOne(m => m.User).WithMany(u => u.Memberships).HasForeignKey(m => m.UserId);
            e.HasOne(m => m.Tenant).WithMany().HasForeignKey(m => m.TenantId);
        });

        builder.Entity<CollectorAgent>(e =>
        {
            e.HasIndex(a => new { a.TenantId, a.Name }).IsUnique();
            e.HasIndex(a => a.CertificateThumbprint).IsUnique();
            e.HasOne(a => a.Tenant).WithMany(t => t.Agents).HasForeignKey(a => a.TenantId);
            e.Property(a => a.ConfigJson).HasColumnType("jsonb");
        });

        builder.Entity<EnrollmentToken>(e => e.HasIndex(t => t.TokenHash).IsUnique());
        builder.Entity<DropRuleEntity>(e =>
        {
            e.ToTable("DropRules");
            e.Property(r => r.Match).HasMaxLength(16);
            e.HasOne(r => r.Tenant).WithMany().HasForeignKey(r => r.TenantId).OnDelete(DeleteBehavior.Cascade);
        });
        builder.Entity<AlertRule>(e =>
        {
            e.HasIndex(a => a.Name).IsUnique();
            e.HasOne(a => a.Tenant).WithMany().HasForeignKey(a => a.TenantId).OnDelete(DeleteBehavior.Cascade);
        });
        builder.Entity<AlertFiring>(e =>
        {
            e.HasIndex(f => new { f.AlertRuleId, f.FiredAt });
            e.HasIndex(f => new { f.AlertRuleId, f.SuppressionKey, f.FiredAt });
            e.HasIndex(f => f.FiredAt);
            e.HasOne(f => f.AlertRule).WithMany().HasForeignKey(f => f.AlertRuleId).OnDelete(DeleteBehavior.Cascade);
            e.Property(f => f.ActionResultsJson).HasColumnType("jsonb");
            e.Property(f => f.SampleJson).HasColumnType("jsonb");
        });
        builder.Entity<AppSetting>(e => e.HasKey(s => s.Key));
        builder.Entity<Dashboard>(e =>
        {
            e.HasIndex(d => d.Name).IsUnique();
            e.Property(d => d.LayoutJson).HasColumnType("jsonb");
        });
    }
}
