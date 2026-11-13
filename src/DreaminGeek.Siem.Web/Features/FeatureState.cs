using DreaminGeek.Siem.Alerting;

namespace DreaminGeek.Siem.Web.Features;

/// <summary>
/// Which optional parts of DG SIEM are switched on (Administration &gt; Features), cached so the menu can check it on
/// every page without a database read. Saving here updates the cache straight away.
/// </summary>
public sealed class FeatureState(SettingsStore settings)
{
    private FeatureSettings? _current;

    public async Task<FeatureSettings> GetAsync(CancellationToken ct) => Volatile.Read(ref _current) ?? await LoadAsync(ct);

    public async Task SaveAsync(FeatureSettings value, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(value);
        await settings.SaveFeaturesAsync(value, ct);
        Volatile.Write(ref _current, value);
    }

    private async Task<FeatureSettings> LoadAsync(CancellationToken ct)
    {
        var loaded = await settings.GetFeaturesAsync(ct);
        Volatile.Write(ref _current, loaded);
        return loaded;
    }
}
