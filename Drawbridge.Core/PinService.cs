using System.Security.Cryptography;
using System.Text.Json;

namespace Drawbridge.Core;

/// <summary>Stores and verifies a salted PBKDF2-SHA-256 parent PIN hash.</summary>
public sealed class PinService
{
    /// <summary>The PBKDF2 iteration count used for newly set PINs.</summary>
    public const int Pbkdf2Iterations = 100_000;

    private const int SaltLength = 16;
    private const int HashLength = 32;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
    };

    private readonly object _sync = new();
    private readonly DrawbridgePaths _paths;

    /// <summary>Creates a PIN service using machine-wide storage.</summary>
    /// <param name="paths">Optional storage paths.</param>
    public PinService(DrawbridgePaths? paths = null)
    {
        _paths = paths ?? new DrawbridgePaths();
        _paths.EnsureCreated();
        if (File.Exists(_paths.PinFile))
        {
            _paths.ProtectSensitiveFile(_paths.PinFile);
        }
    }

    /// <summary>Gets whether a PIN hash file currently exists.</summary>
    public bool HasPin => File.Exists(_paths.PinFile);

    /// <summary>Replaces the parent PIN using a fresh cryptographic salt.</summary>
    /// <param name="pin">The PIN to hash; it is never persisted in plaintext.</param>
    public void SetPin(string pin)
    {
        ValidatePin(pin);
        byte[] salt = RandomNumberGenerator.GetBytes(SaltLength);
        byte[] hash = Derive(pin, salt, Pbkdf2Iterations);
        try
        {
            var record = new PinRecord
            {
                Version = 1,
                Algorithm = "PBKDF2-SHA256",
                Iterations = Pbkdf2Iterations,
                Salt = Convert.ToBase64String(salt),
                Hash = Convert.ToBase64String(hash),
            };

            lock (_sync)
            {
                _paths.EnsureCreated();
                WriteProtectedRecord(record);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
            CryptographicOperations.ZeroMemory(salt);
        }
    }

    /// <summary>Checks a candidate PIN in constant time after deriving its PBKDF2 hash.</summary>
    /// <param name="pin">The candidate PIN.</param>
    /// <returns><see langword="true"/> only when a valid stored record matches.</returns>
    public bool Verify(string pin)
    {
        if (pin is null || pin.Length > 256)
        {
            return false;
        }

        try
        {
            PinRecord? record;
            lock (_sync)
            {
                if (!File.Exists(_paths.PinFile))
                {
                    return false;
                }

                record = JsonSerializer.Deserialize<PinRecord>(
                    File.ReadAllText(_paths.PinFile), JsonOptions);
            }

            if (record is null || record.Iterations is < 10_000 or > 1_000_000 ||
                (!string.IsNullOrEmpty(record.Algorithm) &&
                 !string.Equals(record.Algorithm, "PBKDF2-SHA256", StringComparison.OrdinalIgnoreCase)))
            {
                return false;
            }

            byte[] salt = Convert.FromBase64String(record.Salt ?? string.Empty);
            byte[] expected = Convert.FromBase64String(record.Hash ?? string.Empty);
            if (salt.Length < 8 || salt.Length > 64 || expected.Length != HashLength)
            {
                return false;
            }

            byte[] actual = Derive(pin, salt, record.Iterations);
            try
            {
                return CryptographicOperations.FixedTimeEquals(expected, actual);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(actual);
                CryptographicOperations.ZeroMemory(expected);
                CryptographicOperations.ZeroMemory(salt);
            }
        }
        catch
        {
            // Corrupt, partially written, or legacy-incompatible records fail closed.
            return false;
        }
    }

    /// <summary>Deletes the stored PIN hash.</summary>
    /// <returns><see langword="true"/> when a PIN file was removed.</returns>
    public bool RemovePin()
    {
        lock (_sync)
        {
            if (!File.Exists(_paths.PinFile))
            {
                return false;
            }

            File.Delete(_paths.PinFile);
            return true;
        }
    }

    /// <summary>
    /// Imports a legacy PBKDF2 record without exposing the plaintext PIN and applies the
    /// production SYSTEM/Administrators-only file ACL before publishing it.
    /// </summary>
    /// <param name="json">A serialized legacy or current PIN record.</param>
    public void ImportLegacyRecord(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        PinRecord? record = JsonSerializer.Deserialize<PinRecord>(json, JsonOptions);
        if (!IsValidRecord(record))
        {
            throw new InvalidDataException("The legacy PIN record is invalid.");
        }

        lock (_sync)
        {
            _paths.EnsureCreated();
            WriteProtectedRecord(record!);
        }
    }

    private static byte[] Derive(string pin, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(
            pin,
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            HashLength);

    private void WriteProtectedRecord(PinRecord record) =>
        AtomicFile.WriteAllText(
            _paths.PinFile,
            JsonSerializer.Serialize(record, JsonOptions),
            temporaryPath => _paths.ProtectSensitiveFile(temporaryPath));

    private static bool IsValidRecord(PinRecord? record)
    {
        if (record is null || record.Iterations is < 10_000 or > 1_000_000 ||
            (!string.IsNullOrEmpty(record.Algorithm) &&
             !string.Equals(record.Algorithm, "PBKDF2-SHA256", StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        try
        {
            byte[] salt = Convert.FromBase64String(record.Salt ?? string.Empty);
            byte[] hash = Convert.FromBase64String(record.Hash ?? string.Empty);
            bool valid = salt.Length is >= 8 and <= 64 && hash.Length == HashLength;
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(hash);
            return valid;
        }
        catch
        {
            return false;
        }
    }

    private static void ValidatePin(string pin)
    {
        ArgumentNullException.ThrowIfNull(pin);
        if (pin.Length is < 1 or > 256)
        {
            throw new ArgumentException("PIN must contain between 1 and 256 characters.", nameof(pin));
        }
    }

    private sealed class PinRecord
    {
        public int Version { get; set; }

        public string? Algorithm { get; set; }

        public int Iterations { get; set; } = Pbkdf2Iterations;

        public string? Salt { get; set; }

        public string? Hash { get; set; }
    }
}
