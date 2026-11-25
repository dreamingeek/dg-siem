using DreaminGeek.Siem.Alerting;
using DreaminGeek.Siem.Web.Admin;
using DreaminGeek.Siem.Web.Security;

namespace DreaminGeek.Siem.Tests;

public sealed class SsoTests
{
    private static SsoSettings On(string? authority = "https://auth.example.com/application/o/dg-siem", string? clientId = "dg-siem", string? secret = "s3cret") =>
        new(true, authority, clientId, secret, null);

    [Fact]
    public void The_provider_address_gets_its_trailing_slash_and_fields_are_trimmed()
    {
        var s = SsoService.Validate(On() with { ClientId = "  dg-siem ", Label = " DG Auth " }, "s3cret");
        Assert.Equal("https://auth.example.com/application/o/dg-siem/", s.Authority);
        Assert.Equal("dg-siem", s.ClientId);
        Assert.Equal("DG Auth", s.Label);
        Assert.Equal("DG Auth", s.ButtonLabel);
        Assert.Equal("Authentik", (s with { Label = null }).ButtonLabel);
    }

    [Theory]
    [InlineData("auth.example.com/application/o/dg-siem/")]
    [InlineData("ftp://auth.example.com/")]
    [InlineData("https://auth.example.com/?x=1")]
    public void A_bad_provider_address_is_refused(string authority) =>
        Assert.Throws<AdminException>(() => SsoService.Validate(On(authority), "s3cret"));

    [Fact]
    public void Turning_it_on_needs_the_address_client_and_secret()
    {
        Assert.Throws<AdminException>(() => SsoService.Validate(On(authority: null), "s3cret"));
        Assert.Throws<AdminException>(() => SsoService.Validate(On(clientId: " "), "s3cret"));
        // No new secret and none saved.
        Assert.Throws<AdminException>(() => SsoService.Validate(On(secret: null), null));
        // No new secret, but one is saved: fine, and the saved one is kept (null).
        Assert.Null(SsoService.Validate(On(secret: null), "saved").ClientSecret);
        // Off can be saved half-filled.
        Assert.False(SsoService.Validate(new SsoSettings(false, null, null, null, null), null).Enabled);
    }

    [Fact]
    public void Ready_only_when_on_and_complete()
    {
        Assert.True(On().Ready);
        Assert.False((On() with { Enabled = false }).Ready);
        Assert.False(On(secret: null).Ready);
    }

    [Fact]
    public void The_redirect_uri_uses_the_public_url_when_set()
    {
        Assert.Equal("https://siem.example.com/signin-oidc", Sso.RedirectUri("https://siem.example.com/", "http://10.0.0.5:8080/"));
        Assert.Equal("http://10.0.0.5:8080/signin-oidc", Sso.RedirectUri(null, "http://10.0.0.5:8080/"));
    }
}
