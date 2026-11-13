using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace DreaminGeek.Siem.Data;

/// <summary>Lets <c>dotnet ef migrations add</c> run without starting the web host.</summary>
public sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<SiemDbContext>
{
    public SiemDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<SiemDbContext>()
            .UseNpgsql("Host=localhost;Database=dgsiem;Username=dgsiem;Password=design-time")
            .Options);
}
