using DreaminGeek.Siem.Core;
using DreaminGeek.Siem.Parsers;
using DreaminGeek.Siem.Parsers.Vendors;

namespace DreaminGeek.Siem.Tests;

public class AuthentikParserTests
{
    private static readonly DateTimeOffset Received = new(2026, 11, 12, 5, 20, 0, TimeSpan.Zero);
    private readonly ParserRegistry _registry = new([new TraefikParser(), new AuthentikParser(), new UnifiParser(), new SyslogParser()]);

    private const string Header = "<30>1 2026-11-11T23:20:01.123456-06:00 authentik authentik 323 - - ";

    private LogEvent Parse(string line) => _registry.Parse(new RawEnvelope(Received, "syslog-tcp", "10.0.1.50", line), "dg");

    // Shapes from authentik's Event.save() ("Created Event") with structlog's JSON renderer.
    private const string Login =
        """{"action": "login", "client_ip": "203.0.113.5", "context": {"auth_method": "password", "auth_method_args": {}, "http_request": {"args": {}, "method": "GET", "path": "/api/v3/flows/executor/default-authentication-flow/", "request_id": "5f1c", "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}, "geo": {"city": "Milton", "continent": "NA", "country": "US", "lat": 47.25, "long": -122.31}, "asn": {"asn": 64500, "as_org": "EXAMPLE-ISP", "network": "203.0.113.0/24"}}, "domain_url": "auth.example.com", "event": "Created Event", "host": "auth.example.com", "level": "info", "logger": "authentik.events.models", "pid": 601755, "request_id": "5f1c", "schema_name": "public", "timestamp": "2026-11-12T05:20:01.120000", "user": {"email": "jdoe@example.com", "pk": 7, "username": "jdoe"}}""";

    private const string LoginFailed =
        """{"action": "login_failed", "client_ip": "198.51.100.23", "context": {"username": "admin", "password": "********************", "stage": {"pk": "8d1c", "app": "authentik_stages_password", "name": "default-authentication-password", "model_name": "passwordstage"}, "http_request": {"args": {}, "method": "POST", "path": "/api/v3/flows/executor/default-authentication-flow/", "user_agent": "python-requests/2.32"}}, "event": "Created Event", "level": "info", "logger": "authentik.events.models", "pid": 601755, "timestamp": "2026-11-12T05:20:01.120000", "user": {"username": "AnonymousUser", "pk": 1, "email": "", "is_anonymous": true}}""";

    [Fact]
    public void LoginBecomesAnAuthenticationEvent()
    {
        var e = Parse(Header + Login);

        Assert.Equal("authentik.event", e.EventDataset);
        Assert.Equal("login", e.EventAction);
        Assert.Equal("success", e.EventOutcome);
        Assert.Equal("informational", e.LogLevel);
        Assert.Equal("jdoe", e.UserName);
        Assert.Equal("203.0.113.5", e.SourceIp);
        Assert.Equal("authentik", e.HostName);
        Assert.Equal("login jdoe from 203.0.113.5", e.Message);
        Assert.Equal(new DateTimeOffset(2026, 11, 12, 5, 20, 1, 123, TimeSpan.Zero), e.Timestamp, TimeSpan.FromMilliseconds(1));

        var f = e.Fields;
        Assert.Equal("authentication", f["event.category"]);
        Assert.Equal("jdoe@example.com", f["user.email"]);
        Assert.Equal("US", f["source.geo.country_iso_code"]);
        Assert.Equal("Milton", f["source.geo.city_name"]);
        Assert.Equal("64500", f["source.as.number"]);
        Assert.Equal("EXAMPLE-ISP", f["source.as.organization.name"]);
        Assert.Equal("password", f["authentik.auth_method"]);
        Assert.Equal("/api/v3/flows/executor/default-authentication-flow/", f["url.path"]);
        Assert.Equal("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", f["user_agent.original"]);
    }

    [Fact]
    public void FailedLoginKeepsTheTriedUsername()
    {
        var e = Parse(Header + LoginFailed);

        Assert.Equal("login_failed", e.EventAction);
        Assert.Equal("failure", e.EventOutcome);
        Assert.Equal("warning", e.LogLevel);
        Assert.Equal("admin", e.UserName);
        Assert.Equal("198.51.100.23", e.SourceIp);
        Assert.Equal("default-authentication-password", e.Fields["authentik.stage.name"]);
        Assert.False(e.Fields.ContainsKey("user.email"));
        Assert.DoesNotContain("password\":", string.Join(",", e.Fields.Values), StringComparison.Ordinal);
        Assert.Equal("login_failed admin from 198.51.100.23", e.Message);
    }

    // Sample lines from an authentik host (RFC 3164 from the old rsyslog forwarding).
    [Fact]
    public void ServerRequestsAreHttpEvents()
    {
        var e = Parse("""<30>Nov 11 23:11:55 authentik authentik[601755]: {"auth_via": "secret_key", "domain_url": "localhost", "event": "/api/v3/outposts/proxy/?page=1&page_size=100", "host": "localhost", "level": "info", "logger": "authentik.asgi", "method": "GET", "pid": 601755, "remote": "::1", "request_id": "9f62b5a4bcd94020a7ade2e7a1b45b30", "runtime": 467, "schema_name": "public", "scheme": "http", "status": 200, "timestamp": "2026-11-12T05:11:55.573604", "user": "ak-outpost-53b27a05350c43ff87594db59014bee8", "user_agent": "goauthentik.io/outpost/2026.8.0"}""");

        Assert.Equal("authentik.http", e.EventDataset);
        Assert.Equal("GET", e.Fields["http.request.method"]);
        Assert.Equal("200", e.Fields["http.response.status_code"]);
        Assert.Equal("/api/v3/outposts/proxy/", e.Fields["url.path"]);
        Assert.Equal("467000000", e.Fields["event.duration"]);
        Assert.Equal("::1", e.SourceIp);
        Assert.Equal("ak-outpost-53b27a05350c43ff87594db59014bee8", e.UserName);
        Assert.Equal("success", e.EventOutcome);
    }

    [Fact]
    public void TaskChatterGetsItsOwnDataset()
    {
        var e = Parse("""<30>Nov 11 23:09:19 authentik authentik[323]: {"domain_url": null, "event": "Task finished", "exc": null, "level": "info", "logger": "authentik.tasks.middleware", "pid": 323, "schema_name": "public", "task_id": "163009fe-3d1b-438e-a772-7670167fc154", "task_name": "authentik.core.tasks.clean_temporary_users", "timestamp": "2026-11-12T05:09:19.198700"}""");
        Assert.Equal("authentik.tasks", e.EventDataset);
        Assert.Equal("authentik.core.tasks.clean_temporary_users", e.Fields["authentik.task.name"]);

        var scheduler = Parse("""<30>Nov 11 23:10:18 authentik authentik[323]: {"domain_url": null, "event": "Sent 0 scheduled tasks", "level": "info", "logger": "django_dramatiq_postgres.scheduler", "pid": 323, "schema_name": "public", "timestamp": "2026-11-12T05:10:18.912389"}""");
        Assert.Equal("authentik.tasks", scheduler.EventDataset);
    }

    [Fact]
    public void FailedTasksStayVisible()
    {
        var e = Parse("""<27>Nov 11 23:09:19 authentik authentik[323]: {"event": "Task finished", "exc": "ValueError: boom", "level": "error", "logger": "authentik.tasks.middleware", "task_name": "authentik.core.tasks.clean_temporary_users", "timestamp": "2026-11-12T05:09:19.198700"}""");
        Assert.Equal("authentik.server", e.EventDataset);
        Assert.Equal("error", e.LogLevel);
        Assert.Equal("ValueError: boom", e.Fields["error.message"]);
    }

    [Fact]
    public void OutpostAndSlowQueryLines()
    {
        var outpost = Parse("""<30>Nov 11 23:11:55 authentik authentik[118]: {"filename":"src/outpost/proxy/mod.rs","level":"info","line_number":160,"pid":118,"spans":[{"name":"handle_event"},{"name":"refresh"}],"target":"authentik::outpost::proxy","thread_id":"ThreadId(3)","thread_name":"tokio-1","timestamp":"2026-11-11T23:11:55.582429","event":"loaded application","host":"app.proxy.example.com","name":"Provider for Sonarr SSO","name":"refresh"}""");
        Assert.Equal("authentik.outpost", outpost.EventDataset);
        Assert.Equal("loaded application", outpost.Message);
        Assert.Equal("app.proxy.example.com", outpost.Fields["url.domain"]);

        var slow = Parse("""<28>Nov 11 23:15:36 authentik authentik[316]: {"filename":"/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/sqlx-core-0.9.0/src/logger.rs","level":"warn","line_number":121,"pid":316,"target":"sqlx::query","thread_id":"ThreadId(5)","thread_name":"tokio-2","timestamp":"2026-11-11T23:15:36.632823","elapsed":"1.452002273s","event":"slow statement: execution time exceeded alert threshold","rows_affected":1}""");
        Assert.Equal("authentik.server", slow.EventDataset);
        Assert.Equal("warning", slow.LogLevel);
        Assert.Equal("sqlx::query", slow.Fields["authentik.logger"]);
    }

    [Fact]
    public void OtherJsonWithAnEventFieldIsNotClaimed()
    {
        var e = Parse("""<30>Nov 11 23:11:55 web01 myapp[1]: {"event": "user signed up", "level": "info", "logger": "myapp.accounts"}""");
        Assert.Equal("syslog", e.EventDataset);
    }
}
