using ClickHouse.Driver;
using DreaminGeek.Siem.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace DreaminGeek.Siem.Storage.ClickHouse;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddDgSiemClickHouse(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<ClickHouseOptions>(configuration.GetSection(ClickHouseOptions.SectionName));
        services.AddSingleton(sp => new ClickHouseClient(sp.GetRequiredService<IOptions<ClickHouseOptions>>().Value.ConnectionString));
        services.AddSingleton<ClickHouseMigrator>();
        services.AddSingleton<SourceActivity>();
        services.AddSingleton<TenantRowPolicies>();
        services.AddSingleton<ClickHouseStorage>();
        services.AddSingleton<IEventSink, ClickHouseEventSink>();
        services.AddSingleton<DreaminGeek.Siem.Query.IQueryExecutor, ClickHouseQueryExecutor>();
        services.AddSingleton<DreaminGeek.Siem.Query.IQueryParser, DreaminGeek.Siem.Query.PipeParser>();
        services.AddSingleton<DreaminGeek.Siem.Query.IQueryCompiler>(sp =>
            new DreaminGeek.Siem.Query.ClickHouseCompiler(sp.GetRequiredService<IOptions<ClickHouseOptions>>().Value.Database));
        return services;
    }
}
