using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Drawbridge.Core;

/// <summary>
/// Manages remote blocklists in Adblock syntax (||domain.com^).
///
/// Robustness model:
///  - Every downloaded list is cached in %AppData%\Drawbridge\cache, so
///    the filter loads instantly at launch and works with no internet.
///  - Update checks use conditional HTTP requests (ETag / Last-Modified):
///    unchanged lists cost a ~300-byte "304 Not Modified" instead of a
///    multi-megabyte re-download.
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

    /// <summary>The blocklist source URLs (persisted).</summary>
    public List<string> Urls { get; private set; } = new();

    // Per-URL HTTP caching info (ETag etc.), persisted next to the cache files
    private Dictionary<string, CacheMeta> _meta = new();

    private record CacheMeta(string? Etag, string? LastModified, DateTime FetchedUtc);

    // Merged set of blocked domains; rebuilt fresh and swapped atomically
    private HashSet<string> _blocked = new();

    public int BlockedDomainCount => _blocked.Count;

    public event Action<string>? Log;

    // ---------- lifecycle ----------

    /// <summary>
    /// Launch sequence: load cached lists immediately (works offline),
    /// then check the network for updates.
    /// </summary>
    public async Task InitializeAsync()
    {
        LoadMeta();
        RebuildFromCache();
        await CheckForUpdatesAsync();
    }

    // ---------- settings ----------

    public void LoadSettings()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                var saved = JsonSerializer.Deserialize<List<string>>(
                    File.ReadAllText(SettingsPath));
                if (saved is { Count: > 0 })
                {
                    Urls = saved;
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
            File.WriteAllText(SettingsPath,
                JsonSerializer.Serialize(Urls,
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
        // No cache yet — the next CheckForUpdatesAsync() downloads it in full
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

    // ---------- cache ----------

    /// <summary>Rebuilds the blocked-domain set purely from cached files.</summary>
    public void RebuildFromCache()
    {
        var fresh = new HashSet<string>(StringComparer.Ordinal);
        int listsLoaded = 0;

        foreach (string url in Urls)
        {
            string path = CachePathFor(url);
            if (!File.Exists(path)) continue;

            try
            {
                foreach (string domain in ParseAdblock(File.ReadAllText(path)))
                    fresh.Add(domain);
                listsLoaded++;
            }
            catch (Exception ex)
            {
                Log?.Invoke($"Cache read failed for {url}: {ex.Message}");
            }
        }

        _blocked = fresh; // atomic swap
        Log?.Invoke(listsLoaded > 0
            ? $"Loaded {fresh.Count:N0} domains from local cache ({listsLoaded} list(s))"
            : "No cached lists yet — will download");
    }

    /// <summary>
    /// Asks each list's server "changed since last time?". Downloads only
    /// what actually changed (or was never cached). Returns how many lists
    /// were updated. Network failures keep the existing cache — the filter
    /// never loses data because a check failed.
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

                // Only ask conditionally if we actually still have the cache
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

    private void LoadMeta()
    {
        try
        {
            if (File.Exists(MetaPath))
                _meta = JsonSerializer.Deserialize<Dictionary<string, CacheMeta>>(
                            File.ReadAllText(MetaPath)) ?? new();
        }
        catch
        {
            _meta = new(); // corrupt meta just means full re-downloads
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

    /// <summary>Each URL gets a stable cache filename derived from its hash.</summary>
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
    /// True if the domain or ANY parent domain is on the list, so
    /// "videos.badsite.com" is caught by an entry for "badsite.com".
    /// </summary>
    public bool IsBlocked(string domain)
    {
        string d = domain;
        while (true)
        {
            if (_blocked.Contains(d))
                return true;

            int dot = d.IndexOf('.');
            if (dot < 0)
                return false;

            d = d[(dot + 1)..];
        }
    }
}