using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace Drawbridge.Core;

/// <summary>
/// Stores and checks the parent PIN. Only a salted PBKDF2 hash is written
/// to disk — the PIN itself is never saved anywhere.
/// </summary>
public class PinService
{
    private record PinRecord(string Salt, string Hash);

    private static readonly string PinPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "Drawbridge", "pin.json");

    public bool HasPin => File.Exists(PinPath);

    public void SetPin(string pin)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] hash = Derive(pin, salt);

        Directory.CreateDirectory(Path.GetDirectoryName(PinPath)!);
        File.WriteAllText(PinPath, JsonSerializer.Serialize(new PinRecord(
            Convert.ToBase64String(salt),
            Convert.ToBase64String(hash))));
    }

    public bool Verify(string pin)
    {
        if (!HasPin) return false;

        try
        {
            var rec = JsonSerializer.Deserialize<PinRecord>(File.ReadAllText(PinPath));
            if (rec is null) return false;

            byte[] salt = Convert.FromBase64String(rec.Salt);
            byte[] expected = Convert.FromBase64String(rec.Hash);
            byte[] actual = Derive(pin, salt);

            // Constant-time comparison — no timing hints for guessers
            return CryptographicOperations.FixedTimeEquals(expected, actual);
        }
        catch
        {
            return false;
        }
    }

    public void RemovePin()
    {
        if (HasPin) File.Delete(PinPath);
    }

    private static byte[] Derive(string pin, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(pin, salt, 100_000, HashAlgorithmName.SHA256, 32);
}