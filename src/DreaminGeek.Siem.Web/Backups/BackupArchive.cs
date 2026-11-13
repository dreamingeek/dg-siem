using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace DreaminGeek.Siem.Web.Backups;

public sealed class BackupException(string message) : Exception(message);

/// <summary>
/// The config backup file (<c>.dgsb</c>): a zip of named entries, encrypted with AES-256-GCM under a key derived
/// from the backup passphrase (PBKDF2-SHA256). Layout: <c>"DGSB1"</c>, 16-byte salt, 12-byte nonce, 16-byte tag,
/// ciphertext. The zip holds the agent CA, the data-protection key ring and the PostgreSQL export, so it must
/// never be written unencrypted.
/// </summary>
public static class BackupArchive
{
    private static readonly byte[] Magic = "DGSB1"u8.ToArray();
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int Iterations = 600_000;
    public const int MinPassphraseLength = 12;

    public static byte[] Write(IReadOnlyDictionary<string, byte[]> entries, string passphrase)
    {
        ArgumentNullException.ThrowIfNull(entries);
        CheckPassphrase(passphrase);
        using var zipped = new MemoryStream();
        using (var zip = new ZipArchive(zipped, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, data) in entries.OrderBy(e => e.Key, StringComparer.Ordinal))
            {
                var entry = zip.CreateEntry(name, CompressionLevel.Optimal);
                using var stream = entry.Open();
                stream.Write(data);
            }
        }
        var plain = zipped.ToArray();
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var cipher = new byte[plain.Length];
        var tag = new byte[TagSize];
        using (var aes = new AesGcm(Key(passphrase, salt), TagSize))
        {
            aes.Encrypt(nonce, plain, cipher, tag, Magic);
        }
        CryptographicOperations.ZeroMemory(plain);
        return [.. Magic, .. salt, .. nonce, .. tag, .. cipher];
    }

    public static Dictionary<string, byte[]> Read(ReadOnlySpan<byte> file, string passphrase)
    {
        CheckPassphrase(passphrase);
        var header = Magic.Length + SaltSize + NonceSize + TagSize;
        if (file.Length < header || !file[..Magic.Length].SequenceEqual(Magic))
        {
            throw new BackupException("This isn't a DG SIEM config backup (.dgsb).");
        }
        var salt = file.Slice(Magic.Length, SaltSize);
        var nonce = file.Slice(Magic.Length + SaltSize, NonceSize);
        var tag = file.Slice(Magic.Length + SaltSize + NonceSize, TagSize);
        var cipher = file[header..];
        var plain = new byte[cipher.Length];
        try
        {
            using var aes = new AesGcm(Key(passphrase, salt), TagSize);
            aes.Decrypt(nonce, cipher, tag, plain, Magic);
        }
        catch (AuthenticationTagMismatchException)
        {
            throw new BackupException("Wrong backup passphrase, or the file is damaged.");
        }
        var entries = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        using var zip = new ZipArchive(new MemoryStream(plain), ZipArchiveMode.Read);
        foreach (var entry in zip.Entries)
        {
            using var stream = entry.Open();
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            entries[entry.FullName] = copy.ToArray();
        }
        return entries;
    }

    private static void CheckPassphrase(string passphrase)
    {
        if (string.IsNullOrEmpty(passphrase) || passphrase.Length < MinPassphraseLength)
        {
            throw new BackupException($"Set a backup passphrase of at least {MinPassphraseLength} characters (DGSIEM_BACKUP_PASSPHRASE in .env).");
        }
    }

    private static byte[] Key(string passphrase, ReadOnlySpan<byte> salt) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(passphrase), salt, Iterations, HashAlgorithmName.SHA256, 32);
}
