using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DreaminGeek.Siem.Alerting;

/// <summary>An AlgaPSA call failed; the message is shown to the admin as-is.</summary>
public sealed class PsaException(string message) : Exception(message);

public sealed record PsaTicket(string Id, string Number);

/// <summary>A ticket to open. <paramref name="Lines"/> become paragraphs of the description.</summary>
public sealed record NewPsaTicket(
    string Title, string ClientId, string BoardId, string PriorityId, IReadOnlyList<string> Lines, string? Link, string ExternalId);

/// <summary>
/// AlgaPSA REST API (v1): <c>x-api-key</c> auth, JSON bodies, responses wrapped in <c>{ "data": ... }</c>.
/// Rich text (descriptions, comments) is BlockNote JSON, the format AlgaPSA's own editor stores.
/// </summary>
public sealed class AlgaPsaClient(IHttpClientFactory httpFactory)
{
    public const string HttpClientName = "algapsa";

    public const string ExternalSystem = "dg-siem";
    private const int PageSize = 100;
    private const int MaxPages = 50;

    public async Task<IReadOnlyList<PsaRef>> BoardsAsync(PsaSettings settings, CancellationToken ct)
    {
        var data = await GetDataAsync(settings, $"api/v1/boards?limit={PageSize}", ct);
        return Refs(data, "board_id", "board_name");
    }

    public async Task<IReadOnlyList<PsaRef>> ClientsAsync(PsaSettings settings, CancellationToken ct)
    {
        var all = new List<PsaRef>();
        for (var page = 1; page <= MaxPages; page++)
        {
            var data = await GetDataAsync(settings, $"api/v1/clients?limit={PageSize}&page={page}", ct);
            var refs = Refs(data, "client_id", "client_name");
            all.AddRange(refs);
            if ((data as JsonArray)?.Count < PageSize)
            {
                break;
            }
        }
        return all.DistinctBy(r => r.Id).OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public async Task<IReadOnlyList<PsaRef>> PrioritiesAsync(PsaSettings settings, CancellationToken ct)
    {
        var data = await GetDataAsync(settings, "api/v1/tickets/priorities", ct);
        return Refs(data, "priority_id", "priority_name", sort: false);
    }

    /// <summary>The board's default open status (statuses belong to boards in AlgaPSA).</summary>
    public async Task<string> DefaultStatusAsync(PsaSettings settings, string boardId, CancellationToken ct)
    {
        var data = await GetDataAsync(settings, $"api/v1/tickets/statuses?board_id={Uri.EscapeDataString(boardId)}", ct) as JsonArray ?? [];
        var open = data.OfType<JsonObject>().Where(s => s["is_closed"]?.GetValue<bool>() != true).ToList();
        var chosen = open.FirstOrDefault(s => s["is_default"]?.GetValue<bool>() == true) ?? open.FirstOrDefault();
        return chosen?["status_id"]?.GetValue<string>()
            ?? throw new PsaException("The AlgaPSA board has no open ticket status.");
    }

    public async Task<PsaTicket> CreateTicketAsync(PsaSettings settings, NewPsaTicket ticket, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        var statusId = await DefaultStatusAsync(settings, ticket.BoardId, ct);
        var body = new JsonObject
        {
            ["title"] = ticket.Title.Length > 255 ? ticket.Title[..252] + "..." : ticket.Title,
            ["board_id"] = ticket.BoardId,
            ["client_id"] = ticket.ClientId,
            ["status_id"] = statusId,
            ["priority_id"] = ticket.PriorityId,
            ["attributes"] = new JsonObject { ["description"] = BlockNote(ticket.Lines, ticket.Link) },
        };
        var link = new JsonObject
        {
            ["system"] = ExternalSystem,
            ["external_id"] = ticket.ExternalId,
            ["relationship"] = "origin",
        };
        if (ticket.Link is not null)
        {
            link["url"] = ticket.Link;
        }
        body["external_links"] = new JsonArray(link);

        var data = await SendAsync(settings, HttpMethod.Post, "api/v1/tickets", body, ct);
        var id = data?["ticket_id"]?.GetValue<string>() ?? throw new PsaException("AlgaPSA did not return a ticket id.");
        return new PsaTicket(id, data["ticket_number"]?.GetValue<string>() ?? id);
    }

    /// <summary>False when the ticket is closed or gone.</summary>
    public async Task<bool> IsOpenAsync(PsaSettings settings, string ticketId, CancellationToken ct)
    {
        try
        {
            var data = await GetDataAsync(settings, $"api/v1/tickets/{Uri.EscapeDataString(ticketId)}", ct);
            return data is JsonObject ticket && ticket["closed_at"] is null && ticket["is_closed"]?.GetValue<bool>() != true;
        }
        catch (PsaNotFoundException)
        {
            return false;
        }
    }

    /// <summary>Adds an internal note (not visible to the client).</summary>
    public async Task AddCommentAsync(PsaSettings settings, string ticketId, IReadOnlyList<string> lines, string? link, CancellationToken ct)
    {
        var body = new JsonObject { ["comment_text"] = BlockNote(lines, link), ["is_internal"] = true };
        await SendAsync(settings, HttpMethod.Post, $"api/v1/tickets/{Uri.EscapeDataString(ticketId)}/comments", body, ct);
    }

    /// <summary>One BlockNote paragraph per line, plus an optional link paragraph; serialized as AlgaPSA stores it.</summary>
    internal static string BlockNote(IEnumerable<string> lines, string? link)
    {
        var blocks = new JsonArray();
        foreach (var line in lines)
        {
            blocks.Add(Paragraph(line.Length == 0 ? [] : [Text(line)]));
        }
        if (link is not null)
        {
            blocks.Add(Paragraph([new JsonObject { ["type"] = "link", ["href"] = link, ["content"] = new JsonArray(Text("Open in DG SIEM")) }]));
        }
        return blocks.ToJsonString();

        static JsonObject Text(string text) => new() { ["type"] = "text", ["text"] = text, ["styles"] = new JsonObject() };

        static JsonObject Paragraph(JsonNode[] content) => new()
        {
            ["type"] = "paragraph",
            ["props"] = new JsonObject { ["textColor"] = "default", ["backgroundColor"] = "default", ["textAlignment"] = "left" },
            ["content"] = new JsonArray(content),
            ["children"] = new JsonArray(),
        };
    }

    private static List<PsaRef> Refs(JsonNode? data, string idField, string nameField, bool sort = true)
    {
        var refs = (data as JsonArray ?? [])
            .OfType<JsonObject>()
            .Where(o => o["is_inactive"]?.GetValue<bool>() != true)
            .Select(o => new PsaRef(o[idField]?.GetValue<string>() ?? string.Empty, o[nameField]?.GetValue<string>() ?? "(unnamed)"))
            .Where(r => r.Id.Length > 0);
        return sort ? refs.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ToList() : refs.ToList();
    }

    private Task<JsonNode?> GetDataAsync(PsaSettings settings, string path, CancellationToken ct) =>
        SendAsync(settings, HttpMethod.Get, path, null, ct);

    private async Task<JsonNode?> SendAsync(PsaSettings settings, HttpMethod method, string path, JsonObject? body, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (!settings.IsConfigured)
        {
            throw new PsaException("AlgaPSA isn't set up. Add its URL and API key under Administration → Notifications.");
        }
        if (!Uri.TryCreate(settings.BaseUrl.TrimEnd('/') + "/", UriKind.Absolute, out var baseUri) || baseUri.Scheme is not ("https" or "http"))
        {
            throw new PsaException($"\"{settings.BaseUrl}\" isn't a valid AlgaPSA URL.");
        }

        using var request = new HttpRequestMessage(method, new Uri(baseUri, path));
        request.Headers.Add("x-api-key", settings.ApiKey);
        request.Headers.Accept.ParseAdd("application/json");
        if (body is not null)
        {
            // Buffered with a Content-Length: some proxies in front of AlgaPSA reject chunked request bodies.
            request.Content = new StringContent(body.ToJsonString(), System.Text.Encoding.UTF8, "application/json");
        }

        HttpResponseMessage response;
        try
        {
            response = await httpFactory.CreateClient(HttpClientName).SendAsync(request, ct);
        }
        catch (HttpRequestException ex)
        {
            throw new PsaException($"Couldn't reach AlgaPSA at {baseUri.Host}: {ex.Message}");
        }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new PsaException($"AlgaPSA at {baseUri.Host} didn't answer in time.");
        }

        using (response)
        {
            var text = await response.Content.ReadAsStringAsync(ct);
            if (response.StatusCode == HttpStatusCode.NotFound && method == HttpMethod.Get)
            {
                throw new PsaNotFoundException();
            }
            if (!response.IsSuccessStatusCode)
            {
                throw new PsaException(ErrorMessage(response.StatusCode, text));
            }
            try
            {
                return JsonNode.Parse(text)?["data"];
            }
            catch (JsonException)
            {
                throw new PsaException("AlgaPSA returned something that isn't JSON. Check the URL points at the AlgaPSA server.");
            }
        }
    }

    internal static string ErrorMessage(HttpStatusCode status, string body)
    {
        string? detail = null;
        try
        {
            var error = JsonNode.Parse(body)?["error"];
            detail = error is JsonObject e ? e["message"]?.GetValue<string>() : error?.GetValue<string>();
            if (error?["details"] is JsonArray details && details.Count > 0)
            {
                detail += ": " + string.Join("; ", details.OfType<JsonObject>().Select(d =>
                    $"{string.Join('.', (d["path"] as JsonArray ?? []).Select(p => p?.ToString()))} {d["message"]}".Trim()));
            }
        }
        catch (JsonException)
        {
            // Not JSON (proxy error page); fall through to the status.
        }
        catch (InvalidOperationException)
        {
            // Unexpected shape.
        }

        var hint = status switch
        {
            HttpStatusCode.Unauthorized => " Check the API key.",
            HttpStatusCode.Forbidden => " The API key's user needs permission to read boards/clients and create tickets.",
            _ => string.Empty,
        };
        return $"AlgaPSA said {(int)status} {status}{(detail is null ? "" : $": {detail}")}.{hint}";
    }

    private sealed class PsaNotFoundException() : Exception("Not found");
}
