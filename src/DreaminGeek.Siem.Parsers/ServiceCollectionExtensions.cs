using DreaminGeek.Siem.Parsers.Vendors;
using Microsoft.Extensions.DependencyInjection;

namespace DreaminGeek.Siem.Parsers;

public static class ServiceCollectionExtensions
{
    /// <summary>Registers the built-in parsers (vendor parsers first; generic syslog last).</summary>
    public static IServiceCollection AddDgSiemParsers(this IServiceCollection services)
    {
        services.AddSingleton<IEventParser, WindowsEventParser>();
        services.AddSingleton<IEventParser, AsteriskParser>();
        services.AddSingleton<IEventParser, FreeSwitchParser>();
        services.AddSingleton<IEventParser, TraefikParser>();
        services.AddSingleton<IEventParser, AuthentikParser>();
        services.AddSingleton<IEventParser, CrowdSecParser>();
        services.AddSingleton<IEventParser, UnifiParser>();
        services.AddSingleton<IEventParser, SyslogParser>();
        services.AddSingleton<ParserRegistry>();
        return services;
    }
}
