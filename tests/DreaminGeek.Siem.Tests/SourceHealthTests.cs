using DreaminGeek.Siem.Storage.ClickHouse;

namespace DreaminGeek.Siem.Tests;

public sealed class SourceHealthTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 12, 30, 0, TimeSpan.Zero);

    /// <summary>Activity at the given hours before <see cref="Now"/>'s hour; the last event in the newest of them.</summary>
    private static SourceHealth Judge(IEnumerable<int> hoursAgo, int lastEventMinutesAgo = -1)
    {
        var hour = new DateTimeOffset(Now.Year, Now.Month, Now.Day, Now.Hour, 0, 0, TimeSpan.Zero);
        var hours = hoursAgo.ToList();
        var activity = hours.ToDictionary(h => hour.AddHours(-h), _ => 10L);
        var last = lastEventMinutesAgo >= 0 ? Now.AddMinutes(-lastEventMinutesAgo) : hour.AddHours(-hours.Min()).AddMinutes(50);
        return SourceActivity.Evaluate("acme", "unifi.firewall", "gw1", activity, last, Now);
    }

    [Fact]
    public void Steady_source_is_quiet_after_a_couple_of_silent_hours()
    {
        var sending = Judge(Enumerable.Range(0, 200), lastEventMinutesAgo: 20);
        Assert.Equal(SourceState.Active, sending.State);
        Assert.Equal(TimeSpan.Zero, sending.LongestSilence);
        Assert.Equal(TimeSpan.FromHours(2), sending.QuietAfter);

        var stopped = Judge(Enumerable.Range(3, 200));
        Assert.Equal(SourceState.Quiet, stopped.State);
    }

    [Fact]
    public void Nightly_gap_is_normal_but_missing_more_than_a_night_is_not()
    {
        // Silent 6 hours every day (hours 0-5 of each day-sized block), and currently in such a gap.
        var pattern = Enumerable.Range(0, 200).Where(h => h % 24 >= 6).ToList();
        var inGap = Judge(pattern);
        Assert.Equal(TimeSpan.FromHours(6), inGap.LongestSilence);
        Assert.Equal(TimeSpan.FromHours(14), inGap.QuietAfter);
        Assert.Equal(SourceState.Active, inGap.State);

        // Same pattern, but nothing for the last 20 hours.
        var missed = Judge(pattern.Where(h => h >= 20));
        Assert.Equal(SourceState.Quiet, missed.State);
    }

    [Fact]
    public void Long_silences_cap_at_three_days()
    {
        // Busy on weekdays only: a 60-hour silence every weekend.
        var weekdays = Enumerable.Range(0, 400).Where(h => h % 168 >= 60).ToList();
        var health = Judge(weekdays);
        Assert.Equal(TimeSpan.FromHours(60), health.LongestSilence);
        Assert.Equal(SourceActivity.MaxQuietAfter, health.QuietAfter);
    }

    [Fact]
    public void Stopped_long_ago_stays_quiet_instead_of_fading_out()
    {
        // Steady for a week, then nothing for 6 days: judged on the week before it stopped.
        var health = Judge(Enumerable.Range(6 * 24, 8 * 24));
        Assert.Equal(SourceState.Quiet, health.State);
        Assert.True(health.ActiveHours >= 160);
    }

    [Fact]
    public void New_and_irregular_sources_are_never_quiet()
    {
        Assert.Equal(SourceState.New, Judge(Enumerable.Range(5, 10)).State);
        Assert.Equal(SourceState.Irregular, Judge([30, 90, 150, 200]).State);
    }

    [Fact]
    public void Volume_compares_the_last_day_with_the_usual_day()
    {
        // 10 events every hour for 8 days: 240 in the last day, 240 a day before.
        var health = Judge(Enumerable.Range(0, 8 * 24), lastEventMinutesAgo: 10);
        Assert.Equal(240, health.Events24h);
        Assert.Equal(240, health.UsualPerDay, 0.5);
    }
}
