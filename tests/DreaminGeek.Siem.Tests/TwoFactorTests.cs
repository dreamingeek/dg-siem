using DreaminGeek.Siem.Web.Security;
using Microsoft.AspNetCore.Http;

namespace DreaminGeek.Siem.Tests;

public class TwoFactorTests
{
    [Fact]
    public void OtpAuthUriNamesTheIssuerAndAccount() =>
        Assert.Equal("otpauth://totp/DG%20SIEM:jdoe%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=DG%20SIEM&digits=6",
            TwoFactor.OtpAuthUri("jdoe@example.com", "JBSWY3DPEHPK3PXP"));

    [Fact]
    public void KeyIsGroupedForTyping() =>
        Assert.Equal("JBSW Y3DP EHPK 3PXP AB", TwoFactor.FormatKey("jbswy3dpehpk3pxpab"));

    [Theory]
    [InlineData(" 123 456 ", "123456")]
    [InlineData("ABCD-EFGH", "ABCDEFGH")]
    [InlineData(null, "")]
    public void CodesIgnoreSpacesAndDashes(string? typed, string expected) =>
        Assert.Equal(expected, TwoFactor.CleanCode(typed));

    [Theory]
    [InlineData("BCDF2-GHJK3", "BCDF2-GHJK3")]
    [InlineData(" bcdf2-ghjk3 ", "BCDF2-GHJK3")]
    [InlineData("BCDF2GHJK3", "BCDF2-GHJK3")]
    [InlineData("BCDF2 GHJK3", "BCDF2-GHJK3")]
    public void RecoveryCodesKeepTheirDash(string typed, string expected) =>
        Assert.Equal(expected, TwoFactor.CleanRecoveryCode(typed));

    [Fact]
    public void QrCodeIsSvg()
    {
        var svg = TwoFactor.QrSvg(TwoFactor.OtpAuthUri("jdoe@example.com", "JBSWY3DPEHPK3PXP"));
        Assert.StartsWith("<svg", svg, StringComparison.Ordinal);
        Assert.Contains("#0f1722", svg, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("/account/security", true)]
    [InlineData("/account/logout", true)]
    [InlineData("/_framework/blazor.web.js", true)]
    [InlineData("/_blazor", true)]
    [InlineData("/lib/echarts/echarts.min.js", true)]
    [InlineData("/app.css", true)]
    [InlineData("/search", false)]
    [InlineData("/dashboards", false)]
    [InlineData("/api/v1/search", false)]
    [InlineData("/accounts-export", false)]
    public void OnlyAccountPagesAndAssetsSkipTheRequirement(string path, bool allowed) =>
        Assert.Equal(allowed, TwoFactor.AllowedWithoutTwoFactor(new PathString(path)));

    [Theory]
    [InlineData(null, "/search")]
    [InlineData("/dashboards/abc?x=1", "/dashboards/abc?x=1")]
    [InlineData("//evil.example.com/", "/search")]
    [InlineData("/\\evil.example.com", "/search")]
    [InlineData("https://evil.example.com/", "/search")]
    [InlineData("search", "/search")]
    public void ReturnUrlsStayOnThisSite(string? returnUrl, string expected) =>
        Assert.Equal(expected, ReturnUrls.Safe(returnUrl));
}
