using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;

namespace DreaminGeek.Siem.Core.Agents;

/// <summary>
/// Enrollment tokens look like <c>dgs1_&lt;64-hex secret&gt;_&lt;64-hex CA SHA-256&gt;</c>. The CA fingerprint lets the agent
/// verify the server on first contact, before it has the CA certificate (no trust-on-first-use).
/// The server stores only the SHA-256 of the secret.
/// </summary>
public static class EnrollmentTokenFormat
{
    public const string Prefix = "dgs1";

    public static string Create(string caFingerprintHex, out string secretHash)
    {
        var secret = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        secretHash = HashSecret(secret);
        return $"{Prefix}_{secret}_{caFingerprintHex.ToLowerInvariant()}";
    }

    public static bool TryParse(string token, [NotNullWhen(true)] out string? secret, [NotNullWhen(true)] out string? caFingerprintHex)
    {
        secret = caFingerprintHex = null;
        var parts = (token ?? string.Empty).Trim().Split('_');
        if (parts.Length != 3 || parts[0] != Prefix || parts[1].Length != 64 || !IsHex(parts[1]) || parts[2].Length != 64 || !IsHex(parts[2]))
        {
            return false;
        }
        secret = parts[1];
        caFingerprintHex = parts[2];
        return true;
    }

    public static string HashSecret(string secret) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));

    private static bool IsHex(string s) => s.All(Uri.IsHexDigit);
}
