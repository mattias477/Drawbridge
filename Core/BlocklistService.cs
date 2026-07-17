using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Drawbridge.Core;

/// <summary>
/// Manages blocking sources: remote Adblock-format lists (cached locally,
/// updated via conditional requests), the parent's custom block rules, and
/// an allowlist of exception domains that override the blocklists.
/// Rule precedence is by specificity: walking from the exact hostname up
/// through its parent domains, the first allow/block match wins.
/// </summary>
public class BlocklistService
{
    public const string DefaultUrl =
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt";

    private static readonly string SettingsDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "Drawbridge");

    private static readonly string SettingsPath = Path.Combine(SettingsDir, "blocklists.json");
    private static readonly string CacheDir = Path.Combine(SettingsDir, "cache");
    private static readonly string MetaPath = Path.Combine(CacheDir, "meta.json");

    private class SettingsModel
    {
        public List<string> Urls { get; set; } = new();
        public List<string> CustomDomains { get; set; } = new();
        public List<string> AllowedDomains { get; set; } = new();
    }

    /// <summary>Remote blocklist source URLs (persisted).</summary>
    public List<string> Urls { get; private set; } = new();

    /// <summary>Hand-typed blocked domains (persisted).</summary>
    public List<string> CustomDomains { get; private set; } = new();

    /// <summary>Hand-typed exception domains that are always allowed,
    /// overriding the blocklists (persisted).</summary>
    public List<string> AllowedDomains { get; private set; } = new();

    private Dictionary<string, CacheMeta> _meta = new();

    private record CacheMeta(string? Etag, string? LastModified, DateTime FetchedUtc);

    private HashSet<string> _blocked = new();
    private HashSet<string> _allowed = new();

    public int BlockedDomainCount => _blocked.Count;

    /// <summary>The merged set of every blocked domain (lists + custom).</summary>
    public IReadOnlyCollection<string> BlockedDomains => _blocked;

    public event Action<string>? Log;

    // ---------- settings ----------

    public void LoadSettings()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                string json = File.ReadAllText(SettingsPath);

                // Current format: { Urls, CustomDomains, AllowedDomains }
                try
                {
                    var model = JsonSerializer.Deserialize<SettingsModel>(json);
                    if (model is { Urls.Count: > 0 })
                    {
                        Urls = model.Urls;
                        CustomDomains = model.CustomDomains;
                        AllowedDomains = model.AllowedDomains;
                        return;
                    }
                }
                catch { /* fall through to legacy format */ }

                // Legacy format (pre-custom-rules): plain [ "url", ... ]
                var legacy = JsonSerializer.Deserialize<List<string>>(json);
                if (legacy is { Count: > 0 })
                {
                    Urls = legacy;
                    SaveSettings(); // upgrade the file to the new shape
                    return;
                }
            }
        }
        catch (Exception ex)
        {
            Log?.Invoke($"Couldn't read settings: {ex.Message}");
        }

        Urls = new List<string> { DefaultUrl };
        SaveSettings();
    }

    public void SaveSettings()
    {
        try
        {
            Directory.CreateDirectory(SettingsDir);
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(
                new SettingsModel
                {
                    Urls = Urls,
                    CustomDomains = CustomDomains,
                    AllowedDomains = AllowedDomains,
                },
                new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex)
        {
            Log?.Invoke($"Couldn't save settings: {ex.Message}");
        }
    }

    public void AddList(string url)
    {
        Urls.Add(url);
        SaveSettings();
    }

    public void RemoveList(string url)
    {
        Urls.Remove(url);
        _meta.Remove(url);
        SaveSettings();
        SaveMeta();

        try { File.Delete(CachePathFor(url)); } catch { /* best effort */ }

        RebuildFromCache();
    }

    // ---------- custom rules (block) ----------

    /// <summary>Adds a hand-typed block rule. Returns false if invalid or
    /// already present. Subdomains are blocked automatically.</summary>
    public bool AddCustomDomain(string input)
    {
        string? domain = NormalizeDomain(input);
        if (domain is null || CustomDomains.Contains(domain))
            return false;

        CustomDomains.Add(domain);
        SaveSettings();
        RebuildFromCache();
        Log?.Invoke($"Block rule added: {domain}");
        return true;
    }

    public void RemoveCustomDomain(string domain)
    {
        CustomDomains.Remove(domain);
        SaveSettings();
        RebuildFromCache();
        Log?.Invoke($"Block rule removed: {domain}");
    }

    // ---------- exception rules (allow) ----------

    /// <summary>Adds an always-allow exception. Returns false if invalid or
    /// already present. Subdomains of the exception are allowed too.</summary>
    public bool AddAllowedDomain(string input)
    {
        string? domain = NormalizeDomain(input);
        if (domain is null || AllowedDomains.Contains(domain))
            return false;

        AllowedDomains.Add(domain);
        SaveSettings();
        RebuildFromCache();
        Log?.Invoke($"Allow exception added: {domain}");
        return true;
    }

    public void RemoveAllowedDomain(string domain)
    {
        AllowedDomains.Remove(domain);
        SaveSettings();
        RebuildFromCache();
        Log?.Invoke($"Allow exception removed: {domain}");
    }

    /// <summary>Cleans user input into a bare lowercase hostname,
    /// or null if it doesn't look like one.</summary>
    private static string? NormalizeDomain(string input)
    {
        string domain = input.Trim().ToLowerInvariant()
                             .TrimEnd('.')
                             .Replace("https://", "").Replace("http://", "");

        int slash = domain.IndexOf('/');
        if (slash >= 0) domain = domain[..slash];

        bool looksLikeDomain =
            domain.Length >= 3 &&
            domain.Contains('.') &&
            !domain.Contains(' ') &&
            Uri.CheckHostName(domain) == UriHostNameType.Dns;

        return looksLikeDomain ? domain : null;
    }

    // ---------- cache ----------

    /// <summary>Rebuilds the blocked and allowed sets from cached lists
    /// plus hand-typed rules.</summary>
    public void RebuildFromCache()
    {
        var freshBlocked = new HashSet<string>(StringComparer.Ordinal);
        int listsLoaded = 0;

        foreach (string url in Urls)
        {
            string path = CachePathFor(url);
            if (!File.Exists(path)) continue;

            try
            {
                foreach (string domain in ParseAdblock(File.ReadAllText(path)))
                    freshBlocked.Add(domain);
                listsLoaded++;
            }
            catch (Exception ex)
            {
                Log?.Invoke($"Cache read failed for {url}: {ex.Message}");
            }
        }

        foreach (string domain in CustomDomains)
            freshBlocked.Add(domain);

        _blocked = freshBlocked; // atomic swaps
        _allowed = new HashSet<string>(AllowedDomains, StringComparer.Ordinal);

        Log?.Invoke(listsLoaded > 0 || CustomDomains.Count > 0
            ? $"Loaded {freshBlocked.Count:N0} domains ({listsLoaded} list(s), " +
              $"{CustomDomains.Count} block rule(s), {AllowedDomains.Count} allow exception(s))"
            : "No cached lists yet — will download");
    }

    /// <summary>
    /// Asks each list's server "changed since last time?" using conditional
    /// requests. Downloads only what changed. Network failures keep the
    /// existing cache. Returns how many lists were updated.
    /// </summary>
    public async Task<int> CheckForUpdatesAsync()
    {
        int updated = 0;
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };

        foreach (string url in Urls)
        {
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get, url);
                bool hasCache = File.Exists(CachePathFor(url));

                if (hasCache && _meta.TryGetValue(url, out CacheMeta? meta))
                {
                    if (!string.IsNullOrEmpty(meta.Etag))
                        request.Headers.TryAddWithoutValidation("If-None-Match", meta.Etag);
                    if (!string.IsNullOrEmpty(meta.LastModified))
                        request.Headers.TryAddWithoutValidation("If-Modified-Since", meta.LastModified);
                }

                using HttpResponseMessage response = await http.SendAsync(request);

                if (response.StatusCode == HttpStatusCode.NotModified)
                {
                    Log?.Invoke($"Up to date: {ShortName(url)}");
                    continue;
                }

                response.EnsureSuccessStatusCode();
                string text = await response.Content.ReadAsStringAsync();

                Directory.CreateDirectory(CacheDir);
                File.WriteAllText(CachePathFor(url), text);

                _meta[url] = new CacheMeta(
                    response.Headers.ETag?.ToString(),
                    response.Content.Headers.LastModified?.ToString("R"),
                    DateTime.UtcNow);

                updated++;
                Log?.Invoke($"Updated: {ShortName(url)}");
            }
            catch (Exception ex)
            {
                Log?.Invoke($"Update check failed for {ShortName(url)}: {ex.Message} — keeping cached copy");
            }
        }

        SaveMeta();

        if (updated > 0)
            RebuildFromCache();
        else
            Log?.Invoke($"All lists current — {_blocked.Count:N0} domains active");

        return updated;
    }

    public void LoadMeta()
    {
        try
        {
            if (File.Exists(MetaPath))
                _meta = JsonSerializer.Deserialize<Dictionary<string, CacheMeta>>(
                            File.ReadAllText(MetaPath)) ?? new();
        }
        catch
        {
            _meta = new();
        }
    }

    private void SaveMeta()
    {
        try
        {
            Directory.CreateDirectory(CacheDir);
            File.WriteAllText(MetaPath, JsonSerializer.Serialize(_meta,
                new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex)
        {
            Log?.Invoke($"Couldn't save cache metadata: {ex.Message}");
        }
    }

    private static string CachePathFor(string url)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(url));
        string name = Convert.ToHexString(hash)[..16].ToLowerInvariant();
        return Path.Combine(CacheDir, name + ".txt");
    }

    private static string ShortName(string url)
    {
        try { return Path.GetFileName(new Uri(url).AbsolutePath); }
        catch { return url; }
    }

    // ---------- parsing & checking ----------

    private static IEnumerable<string> ParseAdblock(string text)
    {
        foreach (string raw in text.Split('\n'))
        {
            string line = raw.Trim();

            if (!line.StartsWith("||") || !line.EndsWith("^"))
                continue;

            string domain = line[2..^1].ToLowerInvariant();

            if (domain.Length == 0 || domain.Contains('*') ||
                domain.Contains('/') || domain.Contains('^'))
                continue;

            yield return domain;
        }
    }

    /// <summary>
    /// Walks from the exact hostname up through parent domains. At each
    /// level, an allow exception wins before a block entry — so a specific
    /// allow can punch a hole through a broader block.
    /// </summary>
    public bool IsBlocked(string domain)
    {
        string d = domain;
        while (true)
        {
            if (_allowed.Contains(d))
                return false;

            if (_blocked.Contains(d))
                return true;

            int dot = d.IndexOf('.');
            if (dot < 0)
                return false;

            d = d[(dot + 1)..];
        }
    }
}