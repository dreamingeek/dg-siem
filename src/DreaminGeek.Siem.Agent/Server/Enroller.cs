using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using DreaminGeek.Siem.Core.Agents;

namespace DreaminGeek.Siem.Agent.Server;

public sealed class AgentEnrollmentException(string message) : Exception(message);

/// <summary>
/// Token + CSR → client certificate. First fetch the server's CA and check it against the SHA-256
/// in the token (the token is what authenticates the CA), then enroll over TLS that trusts only that CA.
/// </summary>
public static class Enroller
{
    public static async Task<EnrollResponse> EnrollAsync(AgentStore store, Uri serverUrl, string token, string name, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(store);
        if (!EnrollmentTokenFormat.TryParse(token, out _, out var pin))
        {
            throw new AgentEnrollmentException("The enrollment token is malformed. Copy it again from 'dg-siem-server token create'.");
        }

        var ca = await FetchPinnedCaAsync(serverUrl, pin, ct);
        using var http = ServerClient.CreateHttpClient(serverUrl, h =>
            h.SslOptions.RemoteCertificateValidationCallback = (_, cert, _, errors) => CaPinning.Validate(ca, cert, errors));

        var (keyPem, csrPem) = KeyMaterial.NewKeyAndCsr(name);
        HttpResponseMessage response;
        try
        {
            response = await http.PostAsJsonAsync("api/v1/agents/enroll",
                new EnrollRequest(token.Trim(), name, csrPem, ServerClient.Version, AgentOptions.Platform), AgentJsonContext.Default.EnrollRequest, ct);
        }
        catch (HttpRequestException ex)
        {
            throw new AgentEnrollmentException(
                $"TLS to {serverUrl} failed ({Inner(ex)}). Check that '{serverUrl.Host}' is listed in the server's Pki:AgentHostnames and that the port is forwarded as raw TCP, not through a TLS-terminating proxy.");
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                var detail = await response.Content.ReadAsStringAsync(ct);
                throw new AgentEnrollmentException($"Server refused enrollment ({(int)response.StatusCode}): {detail}");
            }
            var body = await response.Content.ReadFromJsonAsync(AgentJsonContext.Default.EnrollResponse, ct)
                ?? throw new AgentEnrollmentException("Empty enrollment response.");
            store.SaveEnrollment(serverUrl, body, keyPem);
            return body;
        }
    }

    /// <summary>
    /// Downloads the CA without trusting the connection, then accepts it only if its SHA-256 matches
    /// the token. Nothing secret is sent on this request.
    /// </summary>
    private static async Task<X509Certificate2> FetchPinnedCaAsync(Uri serverUrl, string pin, CancellationToken ct)
    {
#pragma warning disable CA5359 // Untrusted fetch on purpose: the response is verified against the pinned hash below.
        using var http = ServerClient.CreateHttpClient(serverUrl, h =>
            h.SslOptions.RemoteCertificateValidationCallback = static (_, _, _, _) => true);
#pragma warning restore CA5359
        string pem;
        try
        {
            pem = await http.GetStringAsync("api/v1/agents/ca", ct);
        }
        catch (HttpRequestException ex)
        {
            throw new AgentEnrollmentException(
                $"Could not reach {serverUrl} ({Inner(ex)}). Check the URL and that the agent port is forwarded as raw TCP.");
        }

        X509Certificate2 ca;
        try
        {
            ca = X509Certificate2.CreateFromPem(pem);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            throw new AgentEnrollmentException($"{serverUrl} did not return a CA certificate. Is this the DG SIEM agent port?");
        }
        if (!CaPinning.MatchesPin(ca, pin))
        {
            ca.Dispose();
            throw new AgentEnrollmentException(
                "The server's CA does not match the enrollment token. Either the token is from a different DG SIEM server, or something is intercepting the connection. Not enrolling.");
        }
        return ca;
    }

    private static string Inner(Exception ex) => ex.InnerException?.Message ?? ex.Message;
}
