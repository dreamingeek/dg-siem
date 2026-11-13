using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace DreaminGeek.Siem.Alerting;

public static class ServiceCollectionExtensions
{
    /// <summary>Alert rules: settings, email, AlgaPSA tickets, and the scheduler.</summary>
    public static IServiceCollection AddDgSiemAlerting(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton<SettingsStore>();
        services.AddSingleton<IEmailSender, SmtpEmailSender>();
        services.AddHttpClient(AlgaPsaClient.HttpClientName, http => http.Timeout = TimeSpan.FromSeconds(30));
        services.AddSingleton<AlgaPsaClient>();
        services.AddSingleton<AlertEvaluator>();
        services.AddSingleton<AlertDispatcher>();
        services.TryAddSingleton<IHealthAlertSource, NoHealthAlerts>();
        services.AddSingleton<AlertRunner>();
        services.AddHostedService<AlertScheduler>();
        return services;
    }
}
