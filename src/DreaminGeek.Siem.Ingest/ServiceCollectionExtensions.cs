using DreaminGeek.Siem.Parsers;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace DreaminGeek.Siem.Ingest;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddDgSiemIngest(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<IngestOptions>(configuration.GetSection(IngestOptions.SectionName));
        services.AddDgSiemParsers();
        services.TryAddSingleton<IDropRuleSource, NoDropRules>();
        services.AddSingleton<DropFilter>();
        services.TryAddSingleton<DreaminGeek.Siem.Ingest.GeoIp.IGeoIpEnricher, DreaminGeek.Siem.Ingest.GeoIp.NoGeoIp>();
        services.TryAddSingleton<DreaminGeek.Siem.Core.RetentionPolicy>();
        services.AddSingleton<IngestPipeline>();
        services.AddHostedService(sp => sp.GetRequiredService<IngestPipeline>());
        return services;
    }
}
