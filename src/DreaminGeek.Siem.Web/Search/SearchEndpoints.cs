using System.Security.Claims;
using DreaminGeek.Siem.Query;
using DreaminGeek.Siem.Web.Security;

namespace DreaminGeek.Siem.Web.Search;

/// <param name="Tenants">Optional subset of the caller's tenants to search; empty = all of them.</param>
public sealed record SearchRequest(string Query, string? Earliest, string? Latest, IReadOnlyList<string>? Tenants);

public static class SearchEndpoints
{
    public static void MapSearchApi(this IEndpointRouteBuilder app)
    {
        // GET /api/v1/search/suggest?q=dataset%3Dunifi.f&pos=16 → autocomplete for the cursor position.
        app.MapGet("/api/v1/search/suggest", async (string? q, int? pos, ClaimsPrincipal user, TenantAccess access, SuggestService suggest, CancellationToken ct) =>
        {
            var userAccess = await access.GetAsync(user, ct);
            if (userAccess is null)
            {
                return Results.Unauthorized();
            }
            var query = q ?? string.Empty;
            return Results.Ok(await suggest.SuggestAsync(userAccess, query, pos ?? query.Length, ct));
        }).RequireAuthorization();

        // POST /api/v1/search {"query":"dataset=unifi.firewall | top src","earliest":"-24h","latest":"now"}
        app.MapPost("/api/v1/search", async (SearchRequest request, ClaimsPrincipal user, TenantAccess access, SearchService search, CancellationToken ct) =>
        {
            var userAccess = await access.GetAsync(user, ct);
            if (userAccess is null)
            {
                return Results.Unauthorized();
            }
            var tenants = TenantAccess.Narrow(userAccess, request.Tenants);
            if (tenants.Count == 0)
            {
                return Results.Problem("You don't have access to any of the requested tenants.", statusCode: StatusCodes.Status403Forbidden);
            }

            var now = DateTimeOffset.UtcNow;
            DateTimeOffset from, to;
            try
            {
                from = SearchService.ParseTime(request.Earliest, now, now.AddHours(-24));
                to = SearchService.ParseTime(request.Latest, now, now);
            }
            catch (Exception ex) when (ex is FormatException or QueryParseException)
            {
                return Results.BadRequest(new { error = "earliest/latest must be like -15m, -24h, now, or an ISO timestamp." });
            }

            var response = await search.RunAsync(request.Query, from, to, tenants, ct);
            if (response.Result is not { } result)
            {
                return Results.BadRequest(new { error = response.Error, position = response.ErrorPosition });
            }
            return Results.Ok(new
            {
                shape = result.Shape.ToString().ToLowerInvariant(),
                columns = result.Columns,
                rows = result.Rows,
                truncated = result.Truncated,
                elapsedMs = (int)result.Elapsed.TotalMilliseconds,
            });
        }).RequireAuthorization();
    }
}
