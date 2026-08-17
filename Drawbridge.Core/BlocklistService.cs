using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Drawbridge.Core;

/// <summary>Specifies how unmatched DNS names are handled.</summary>
public enum FilterMode
{
    /// <summary>Allows names unless a block rule matches.</summary>
    Blocklist,

    /// <summary>Blocks names unless an allow rule or system-essential rule matches.</summary>
    Whitelist,
}

/// <summary>
/// Persists block/allow rules, maintains remote Adblock caches, and makes thread-safe
/// filtering decisions using the most-specific matching rule.
/// </summary>
public sealed class BlocklistService : IDisposable
{
    private const long MaximumDownloadBytes = 128L * 1024 * 1024;

    /// <summary>The default HaGeZi adult-content blocklist.</summary>
    public const string DefaultNsfwUrl =
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt";

    /// <summary>The default HaGeZi DNS-over-HTTPS resolver blocklist.</summary>
    public const string DefaultDohUrl =
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh.txt";

    /// <summary>Firefox's DNS-over-HTTPS canary, blocked on fresh installations.</summary>
    public const string FirefoxDohCanary = "use-application-dns.net";

    /// <summary>Compatibility alias for the primary default blocklist URL.</summary>
    public const string DefaultUrl = DefaultNsfwUrl;

    private static readonly HashSet<string> EssentialDomains = new(StringComparer.Ordinal)
    {
        "msftconnecttest.com",
        "msftncsi.com",
        "windowsupdate.com",
        "update.microsoft.com",
        "windows.com",
        "microsoft.com",
        "time.windows.com",
    };

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly object _settingsLock = new();
    private readonly SemaphoreSlim _updateGate = new(1, 1);
    private readonly DrawbridgePaths _paths;
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>> _hostResolver;
    private List<string> _urls = new();
    private List<string> _customDomains = new();
    private List<string> _allowedDomains = new();
    private Dictionary<string, CacheMetadata> _metadata = new(StringComparer.Ordinal);
    private HashSet<string> _blocked = new(StringComparer.Ordinal);
    private HashSet<string> _allowed = new(StringComparer.Ordinal);
    private FilterMode _mode;
    private bool _disposed;

    /// <summary>
    /// Creates a filtering service and immediately loads persisted settings and caches.
    /// </summary>
    /// <param name="paths">Optional persistent storage paths.</param>
    /// <param name="httpClient">Optional HTTP client, primarily for hosting and tests.</param>
    /// <param name="hostResolver">Optional resolver used to validate that source hosts are public.</param>
    public BlocklistService(
        DrawbridgePaths? paths = null,
        HttpClient? httpClient = null,
        Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>>? hostResolver = null)
    {
        _paths = paths ?? new DrawbridgePaths();
        _paths.EnsureCreated(message => Log?.Invoke(message));

        _ownsHttpClient = httpClient is null;
        _httpClient = httpClient ?? new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.GZip |
                                     DecompressionMethods.Deflate |
                                     DecompressionMethods.Brotli,
        })
        {
            Timeout = TimeSpan.FromSeconds(30),
        };
        _hostResolver = hostResolver ?? ResolveHostAsync;

        LoadSettings();
    }

    /// <summary>Raised for settings, cache, and update diagnostics.</summary>
    public event Action<string>? Log;

    /// <summary>Gets the configured remote Adblock source URLs.</summary>
    public IReadOnlyList<string> Urls
    {
        get { lock (_settingsLock) return _urls.ToArray(); }
    }

    /// <summary>Gets the hand-authored block rules.</summary>
    public IReadOnlyList<string> CustomDomains
    {
        get { lock (_settingsLock) return _customDomains.ToArray(); }
    }

    /// <summary>Gets the allowed-domain rules.</summary>
    public IReadOnlyList<string> AllowedDomains
    {
        get { lock (_settingsLock) return _allowedDomains.ToArray(); }
    }

    /// <summary>Gets the current filtering mode.</summary>
    public FilterMode Mode
    {
        get { lock (_settingsLock) return _mode; }
    }

    /// <summary>Gets the number of distinct active block rules.</summary>
    public int BlockedDomainCount => Volatile.Read(ref _blocked).Count;

    /// <summary>Gets a snapshot of the merged cached and custom block rules.</summary>
    public IReadOnlyCollection<string> BlockedDomains =>
        Volatile.Read(ref _blocked).ToArray();

    /// <summary>Gets the built-in domains which keep Windows operational in whitelist mode.</summary>
    public static IReadOnlySet<string> SystemEssentials =>
        new HashSet<string>(EssentialDomains, StringComparer.Ordinal);

    /// <summary>Reloads settings, metadata, and cached lists from disk.</summary>
    public void LoadSettings()
    {
        ThrowIfDisposed();
        _paths.EnsureCreated(message => Log?.Invoke(message));

        SettingsModel? settings = null;
        bool loadedLegacySettings = false;
        try
        {
            if (File.Exists(_paths.SettingsFile))
            {
                string json = File.ReadAllText(_paths.SettingsFile);
                try
                {
                    settings = JsonSerializer.Deserialize<SettingsModel>(json, JsonOptions);
                }
                catch (JsonException)
                {
                    List<string>? legacyUrls = JsonSerializer.Deserialize<List<string>>(json, JsonOptions);
                    if (legacyUrls is not null)
                    {
                        settings = new SettingsModel
                        {
                            Urls = legacyUrls,
                            CustomDomains = new List<string> { FirefoxDohCanary },
                        };
                        loadedLegacySettings = true;
                    }
                }
            }
            else
            {
                settings = TryLoadLegacySettings();
                loadedLegacySettings = settings is not null;
            }
        }
        catch (Exception ex)
        {
            Log?.Invoke($"Could not read settings: {ex.Message}; using safe defaults.");
        }

        bool createdDefaults = settings is null;
        settings ??= CreateDefaultSettings();

        lock (_settingsLock)
        {
            _urls = DistinctValidUrls(settings.Urls);
            _customDomains = DistinctDomains(settings.CustomDomains);
            _allowedDomains = DistinctDomains(settings.AllowedDomains);
            _mode = Enum.IsDefined(settings.Mode) ? settings.Mode : FilterMode.Blocklist;
            _metadata = LoadMetadata();
        }

        if (createdDefaults || loadedLegacySettings)
        {
            SaveSettings();
        }

        SaveMetadata();
        RebuildFromCache();
    }

    /// <summary>Persists the current source URLs, rules, and filtering mode.</summary>
    public void SaveSettings()
    {
        ThrowIfDisposed();
        SettingsModel model;
        lock (_settingsLock)
        {
            model = new SettingsModel
            {
                Version = 1,
                Urls = _urls.ToList(),
                CustomDomains = _customDomains.ToList(),
                AllowedDomains = _allowedDomains.ToList(),
                Mode = _mode,
            };
        }

        try
        {
            _paths.EnsureCreated(message => Log?.Invoke(message));
            AtomicFile.WriteAllText(_paths.SettingsFile, JsonSerializer.Serialize(model, JsonOptions));
        }
        catch (Exception ex)
        {
            Log?.Invoke($"Could not save settings: {ex.Message}");
        }
    }

    /// <summary>Changes and persists the default-match filtering behavior.</summary>
    /// <param name="mode">The new filtering mode.</param>
    public void SetMode(FilterMode mode)
    {
        if (!Enum.IsDefined(mode))
        {
            throw new ArgumentOutOfRangeException(nameof(mode));
        }

        lock (_settingsLock)
        {
            if (_mode == mode)
            {
                return;
            }

            _mode = mode;
        }

        SaveSettings();
        Log?.Invoke(mode == FilterMode.Whitelist
            ? "Whitelist mode enabled; unmatched domains will be blocked."
            : "Blocklist mode enabled; unmatched domains will be allowed.");
    }

    /// <summary>Adds and persists an HTTP(S) Adblock source URL.</summary>
    /// <returns><see langword="true"/> when the URL was added.</returns>
    public bool AddList(string url)
    {
        string? normalized = NormalizeUrl(url);
        if (normalized is null)
        {
            return false;
        }

        lock (_settingsLock)
        {
            if (_urls.Contains(normalized, StringComparer.Ordinal))
            {
                return false;
            }

            _urls.Add(normalized);
        }

        SaveSettings();
        Log?.Invoke($"Blocklist source added: {normalized}");
        return true;
    }

    /// <summary>Removes a source URL, its metadata, and its cached content.</summary>
    /// <returns><see langword="true"/> when the URL existed.</returns>
    public bool RemoveList(string url)
    {
        string? normalized = NormalizeUrl(url);
        if (normalized is null)
        {
            return false;
        }

        bool removed;
        lock (_settingsLock)
        {
            removed = _urls.Remove(normalized);
            if (removed)
            {
                _metadata.Remove(normalized);
            }
        }

        if (!removed)
        {
            return false;
        }

        SaveSettings();
        SaveMetadata();
        try { File.Delete(CachePathFor(normalized)); } catch { }
        try { File.Delete(LegacyCachePathFor(normalized)); } catch { }
        RebuildFromCache();
        Log?.Invoke($"Blocklist source removed: {normalized}");
        return true;
    }

    /// <summary>Adds a normalized hand-authored block rule.</summary>
    /// <returns><see langword="true"/> when the rule was added.</returns>
    public bool AddCustomDomain(string input) =>
        AddDomain(input, isAllowed: false);

    /// <summary>Removes a hand-authored block rule.</summary>
    /// <returns><see langword="true"/> when the rule existed.</returns>
    public bool RemoveCustomDomain(string input) =>
        RemoveDomain(input, isAllowed: false);

    /// <summary>Adds a normalized allowed-domain rule.</summary>
    /// <returns><see langword="true"/> when the rule was added.</returns>
    public bool AddAllowedDomain(string input) =>
        AddDomain(input, isAllowed: true);

    /// <summary>Removes an allowed-domain rule.</summary>
    /// <returns><see langword="true"/> when the rule existed.</returns>
    public bool RemoveAllowedDomain(string input) =>
        RemoveDomain(input, isAllowed: true);

    /// <summary>
    /// Atomically rebuilds the live filtering sets from all readable caches and custom rules.
    /// </summary>
    public void RebuildFromCache()
    {
        ThrowIfDisposed();
        string[] urls;
        string[] custom;
        string[] allowed;
        lock (_settingsLock)
        {
            urls = _urls.ToArray();
            custom = _customDomains.ToArray();
            allowed = _allowedDomains.ToArray();
        }

        var blocked = new HashSet<string>(StringComparer.Ordinal);
        int cachesLoaded = 0;
        foreach (string url in urls)
        {
            string path = CachePathForRead(url);
            if (!File.Exists(path))
            {
                continue;
            }

            try
            {
                foreach (string domain in ParseAdblock(File.ReadAllText(path)))
                {
                    blocked.Add(domain);
                }

                cachesLoaded++;
            }
            catch (Exception ex)
            {
                Log?.Invoke($"Could not read cached list {ShortName(url)}: {ex.Message}");
            }
        }

        blocked.UnionWith(custom);
        var allowedSet = new HashSet<string>(allowed, StringComparer.Ordinal);
        Volatile.Write(ref _blocked, blocked);
        Volatile.Write(ref _allowed, allowedSet);

        Log?.Invoke($"Loaded {blocked.Count:N0} block rule(s) from {cachesLoaded} cached list(s) and {custom.Length} custom rule(s).");
    }

    /// <summary>
    /// Conditionally refreshes each remote list. Failures and suspicious empty responses leave
    /// the previous on-disk cache and live filtering set untouched.
    /// </summary>
    /// <param name="cancellationToken">Stops the update operation.</param>
    /// <returns>The number of source caches replaced with valid new content.</returns>
    public async Task<int> CheckForUpdatesAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await _updateGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await CheckForUpdatesCoreAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _updateGate.Release();
        }
    }

    private async Task<int> CheckForUpdatesCoreAsync(CancellationToken cancellationToken)
    {
        string[] urls;
        lock (_settingsLock)
        {
            urls = _urls.ToArray();
        }

        int updated = 0;
        foreach (string url in urls)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string cachePath = CachePathFor(url);
            string existingCachePath = CachePathForRead(url);

            try
            {
                CacheMetadata? metadata;
                lock (_settingsLock)
                {
                    _metadata.TryGetValue(url, out metadata);
                }

                using HttpResponseMessage response = await SendValidatedAsync(
                    new Uri(url, UriKind.Absolute),
                    File.Exists(existingCachePath) ? metadata : null,
                    cancellationToken).ConfigureAwait(false);

                if (response.StatusCode == HttpStatusCode.NotModified)
                {
                    Log?.Invoke($"Up to date: {ShortName(url)}");
                    continue;
                }

                response.EnsureSuccessStatusCode();
                string content = await ReadBoundedContentAsync(
                    response.Content, cancellationToken).ConfigureAwait(false);
                IReadOnlyCollection<string> parsed = ParseAdblock(content);

                // A CDN error page can be a successful 200 response. Never let that silently
                // disarm filtering. Rejecting empty first downloads is safer as well.
                if (parsed.Count == 0)
                {
                    Log?.Invoke($"Rejected empty or invalid list from {ShortName(url)}; keeping cached copy.");
                    continue;
                }

                _paths.EnsureCreated(message => Log?.Invoke(message));
                AtomicFile.WriteAllText(cachePath, content);
                if (!string.Equals(cachePath, existingCachePath, StringComparison.OrdinalIgnoreCase))
                {
                    try { File.Delete(existingCachePath); } catch { }
                }
                lock (_settingsLock)
                {
                    // A concurrently removed URL must not be reintroduced in metadata.
                    if (_urls.Contains(url, StringComparer.Ordinal))
                    {
                        _metadata[url] = new CacheMetadata
                        {
                            ETag = response.Headers.ETag?.ToString(),
                            LastModifiedUtc = response.Content.Headers.LastModified,
                            FetchedUtc = DateTimeOffset.UtcNow,
                            DomainCount = parsed.Count,
                        };
                    }
                }

                updated++;
                Log?.Invoke($"Updated {ShortName(url)}: {parsed.Count:N0} domain(s).");
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                Log?.Invoke($"Update failed for {ShortName(url)}: {ex.Message}; keeping cached copy.");
            }
        }

        SaveMetadata();
        if (updated > 0)
        {
            RebuildFromCache();
        }

        return updated;
    }

    /// <summary>
    /// Returns whether a query should receive NXDOMAIN. At every hostname level an allow rule
    /// beats a block rule; the first level with any match decides the result.
    /// </summary>
    /// <param name="domain">A DNS hostname, with or without a trailing dot.</param>
    public bool IsBlocked(string domain)
    {
        string? normalized = NormalizeQueryName(domain);
        FilterMode mode = Mode;
        if (normalized is null)
        {
            return mode == FilterMode.Whitelist;
        }

        HashSet<string> blocked = Volatile.Read(ref _blocked);
        HashSet<string> allowed = Volatile.Read(ref _allowed);
        string candidate = normalized;

        while (true)
        {
            if (allowed.Contains(candidate) ||
                (mode == FilterMode.Whitelist && EssentialDomains.Contains(candidate)))
            {
                return false;
            }

            if (blocked.Contains(candidate))
            {
                return true;
            }

            int dot = candidate.IndexOf('.');
            if (dot < 0)
            {
                break;
            }

            candidate = candidate[(dot + 1)..];
        }

        return mode == FilterMode.Whitelist;
    }

    /// <summary>Parses only canonical <c>||domain^</c> Adblock lines.</summary>
    /// <param name="text">The complete text of an Adblock list.</param>
    /// <returns>A de-duplicated collection of normalized domains.</returns>
    public static IReadOnlyCollection<string> ParseAdblock(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var result = new HashSet<string>(StringComparer.Ordinal);
        using var reader = new StringReader(text);
        while (reader.ReadLine() is { } raw)
        {
            string line = raw.Trim();
            if (line.Length < 5 || !line.StartsWith("||", StringComparison.Ordinal) ||
                !line.EndsWith('^'))
            {
                continue;
            }

            string candidate = line[2..^1];
            if (candidate.IndexOfAny(['*', '/', '^', '|', '$']) >= 0)
            {
                continue;
            }

            string? domain = NormalizeDomain(candidate);
            if (domain is not null)
            {
                result.Add(domain);
            }
        }

        return result;
    }

    /// <summary>Normalizes a user-entered hostname or URL to a bare ASCII DNS hostname.</summary>
    /// <param name="input">A hostname or HTTP(S) URL.</param>
    /// <returns>The normalized hostname, or <see langword="null"/> when invalid.</returns>
    public static string? NormalizeDomain(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return null;
        }

        string candidate = input.Trim();
        if (Uri.TryCreate(candidate, UriKind.Absolute, out Uri? uri))
        {
            if (uri.Scheme is not ("http" or "https") || string.IsNullOrWhiteSpace(uri.Host))
            {
                return null;
            }

            candidate = uri.IdnHost;
        }
        else if (candidate.Contains('/') || candidate.Contains('\\') || candidate.Contains(':'))
        {
            return null;
        }

        candidate = candidate.TrimEnd('.');
        string ascii;
        try
        {
            ascii = new IdnMapping().GetAscii(candidate).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            return null;
        }

        if (ascii.Length is < 3 or > 253 || !ascii.Contains('.') ||
            IPAddress.TryParse(ascii, out _))
        {
            return null;
        }

        string[] labels = ascii.Split('.');
        foreach (string label in labels)
        {
            if (label.Length is < 1 or > 63 || label[0] == '-' || label[^1] == '-' ||
                label.Any(character => !char.IsAsciiLetterOrDigit(character) && character != '-'))
            {
                return null;
            }
        }

        return ascii;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }
    }

    private bool AddDomain(string input, bool isAllowed)
    {
        string? domain = NormalizeDomain(input);
        if (domain is null)
        {
            return false;
        }

        lock (_settingsLock)
        {
            List<string> target = isAllowed ? _allowedDomains : _customDomains;
            if (target.Contains(domain, StringComparer.Ordinal))
            {
                return false;
            }

            target.Add(domain);
            target.Sort(StringComparer.Ordinal);
        }

        SaveSettings();
        RebuildFromCache();
        Log?.Invoke($"{(isAllowed ? "Allow" : "Block")} rule added: {domain}");
        return true;
    }

    private bool RemoveDomain(string input, bool isAllowed)
    {
        string? domain = NormalizeDomain(input);
        if (domain is null)
        {
            return false;
        }

        bool removed;
        lock (_settingsLock)
        {
            List<string> target = isAllowed ? _allowedDomains : _customDomains;
            removed = target.Remove(domain);
        }

        if (!removed)
        {
            return false;
        }

        SaveSettings();
        RebuildFromCache();
        Log?.Invoke($"{(isAllowed ? "Allow" : "Block")} rule removed: {domain}");
        return true;
    }

    private SettingsModel? TryLoadLegacySettings()
    {
        string legacyPath = Path.Combine(_paths.RootDirectory, "blocklists.json");
        if (!File.Exists(legacyPath))
        {
            return null;
        }

        string json = File.ReadAllText(legacyPath);
        try
        {
            SettingsModel? model = JsonSerializer.Deserialize<SettingsModel>(json, JsonOptions);
            if (model is not null)
            {
                return model;
            }
        }
        catch (JsonException)
        {
            // Older releases stored just the URL array.
        }

        List<string>? urls = JsonSerializer.Deserialize<List<string>>(json, JsonOptions);
        return urls is null
            ? null
            : new SettingsModel
            {
                Urls = urls,
                CustomDomains = new List<string> { FirefoxDohCanary },
            };
    }

    private Dictionary<string, CacheMetadata> LoadMetadata()
    {
        try
        {
            string legacyMetadataFile = Path.Combine(_paths.CacheDirectory, "meta.json");
            var result = new Dictionary<string, CacheMetadata>(StringComparer.Ordinal);
            // Migration can copy meta.json after a fresh v2 instance has already created an
            // empty metadata.json. Merge both, with v2 values taking precedence when present.
            foreach (string metadataFile in new[] { legacyMetadataFile, _paths.CacheMetadataFile })
            {
                if (!File.Exists(metadataFile))
                {
                    continue;
                }

                using JsonDocument document = JsonDocument.Parse(File.ReadAllText(metadataFile));
                if (document.RootElement.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                foreach (JsonProperty source in document.RootElement.EnumerateObject())
                {
                    if (source.Value.ValueKind != JsonValueKind.Object)
                    {
                        continue;
                    }

                    var metadata = new CacheMetadata();
                    foreach (JsonProperty property in source.Value.EnumerateObject())
                    {
                        if (property.Name.Equals("ETag", StringComparison.OrdinalIgnoreCase) &&
                            property.Value.ValueKind == JsonValueKind.String)
                        {
                            metadata.ETag = property.Value.GetString();
                        }
                        else if ((property.Name.Equals("LastModifiedUtc", StringComparison.OrdinalIgnoreCase) ||
                                  property.Name.Equals("LastModified", StringComparison.OrdinalIgnoreCase)) &&
                                 property.Value.ValueKind == JsonValueKind.String &&
                                 DateTimeOffset.TryParse(
                                     property.Value.GetString(),
                                     CultureInfo.InvariantCulture,
                                     DateTimeStyles.AssumeUniversal,
                                     out DateTimeOffset lastModified))
                        {
                            metadata.LastModifiedUtc = lastModified;
                        }
                        else if (property.Name.Equals("FetchedUtc", StringComparison.OrdinalIgnoreCase) &&
                                 property.Value.ValueKind == JsonValueKind.String &&
                                 DateTimeOffset.TryParse(
                                     property.Value.GetString(),
                                     CultureInfo.InvariantCulture,
                                     DateTimeStyles.AssumeUniversal,
                                     out DateTimeOffset fetched))
                        {
                            metadata.FetchedUtc = fetched;
                        }
                        else if (property.Name.Equals("DomainCount", StringComparison.OrdinalIgnoreCase) &&
                                 property.Value.TryGetInt32(out int count))
                        {
                            metadata.DomainCount = Math.Max(0, count);
                        }
                    }

                    result[source.Name] = metadata;
                }
            }

            return result;
        }
        catch (Exception ex)
        {
            Log?.Invoke($"Could not read blocklist cache metadata: {ex.Message}");
        }

        return new Dictionary<string, CacheMetadata>(StringComparer.Ordinal);
    }

    private void SaveMetadata()
    {
        Dictionary<string, CacheMetadata> snapshot;
        lock (_settingsLock)
        {
            snapshot = new Dictionary<string, CacheMetadata>(_metadata, StringComparer.Ordinal);
        }

        try
        {
            AtomicFile.WriteAllText(
                _paths.CacheMetadataFile,
                JsonSerializer.Serialize(snapshot, JsonOptions));
        }
        catch (Exception ex)
        {
            Log?.Invoke($"Could not save blocklist cache metadata: {ex.Message}");
        }
    }

    private string CachePathFor(string url)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(url));
        string fileName = $"{Convert.ToHexString(hash).ToLowerInvariant()}.adblock";
        return Path.Combine(_paths.CacheDirectory, fileName);
    }

    private string LegacyCachePathFor(string url)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(url));
        string fileName = $"{Convert.ToHexString(hash)[..16].ToLowerInvariant()}.txt";
        return Path.Combine(_paths.CacheDirectory, fileName);
    }

    private string CachePathForRead(string url)
    {
        string current = CachePathFor(url);
        if (File.Exists(current))
        {
            return current;
        }

        string legacy = LegacyCachePathFor(url);
        if (!File.Exists(legacy))
        {
            return current;
        }

        try
        {
            AtomicFile.WriteAllText(current, File.ReadAllText(legacy));
            File.Delete(legacy);
            return current;
        }
        catch
        {
            return legacy;
        }
    }

    private static SettingsModel CreateDefaultSettings() => new()
    {
        Version = 1,
        Urls = new List<string> { DefaultNsfwUrl, DefaultDohUrl },
        CustomDomains = new List<string> { FirefoxDohCanary },
        AllowedDomains = new List<string>(),
        Mode = FilterMode.Blocklist,
    };

    private static List<string> DistinctValidUrls(IEnumerable<string>? values) =>
        (values ?? [])
            .Select(NormalizeUrl)
            .Where(value => value is not null)
            .Cast<string>()
            .Distinct(StringComparer.Ordinal)
            .ToList();

    private static List<string> DistinctDomains(IEnumerable<string>? values) =>
        (values ?? [])
            .Select(NormalizeDomain)
            .Where(value => value is not null)
            .Cast<string>()
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToList();

    private async Task<HttpResponseMessage> SendValidatedAsync(
        Uri initialUri,
        CacheMetadata? metadata,
        CancellationToken cancellationToken)
    {
        Uri currentUri = initialUri;
        const int maximumRedirects = 5;
        for (int redirectCount = 0; redirectCount <= maximumRedirects; redirectCount++)
        {
            await ValidateRemoteUriAsync(currentUri, cancellationToken).ConfigureAwait(false);
            using var request = new HttpRequestMessage(HttpMethod.Get, currentUri);
            if (metadata is not null)
            {
                if (EntityTagHeaderValue.TryParse(metadata.ETag, out EntityTagHeaderValue? etag))
                {
                    request.Headers.IfNoneMatch.Add(etag);
                }

                if (metadata.LastModifiedUtc is DateTimeOffset modified)
                {
                    request.Headers.IfModifiedSince = modified;
                }
            }

            HttpResponseMessage response = await _httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            try
            {
                // An injected HttpClient may follow redirects itself. Revalidate its final URI;
                // the production-owned handler has redirects disabled and is checked preflight.
                if (response.RequestMessage?.RequestUri is Uri finalUri && finalUri != currentUri)
                {
                    await ValidateRemoteUriAsync(finalUri, cancellationToken).ConfigureAwait(false);
                }

                if (!IsRedirect(response.StatusCode))
                {
                    return response;
                }

                if (redirectCount == maximumRedirects || response.Headers.Location is not Uri location)
                {
                    throw new HttpRequestException("The blocklist returned too many or an invalid redirect.");
                }

                currentUri = location.IsAbsoluteUri ? location : new Uri(currentUri, location);
            }
            catch
            {
                response.Dispose();
                throw;
            }

            response.Dispose();
        }

        throw new HttpRequestException("The blocklist returned too many redirects.");
    }

    private static async Task<string> ReadBoundedContentAsync(
        HttpContent content,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is long declaredLength &&
            declaredLength > MaximumDownloadBytes)
        {
            throw new InvalidDataException("The blocklist download exceeds the 128 MiB safety limit.");
        }

        await using Stream input = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var output = new MemoryStream(
            content.Headers.ContentLength is > 0 and <= MaximumDownloadBytes
                ? (int)content.Headers.ContentLength.Value
                : 0);
        byte[] buffer = new byte[81_920];
        while (true)
        {
            int read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            if (output.Length + read > MaximumDownloadBytes)
            {
                throw new InvalidDataException("The blocklist download exceeds the 128 MiB safety limit.");
            }

            output.Write(buffer, 0, read);
        }

        return Encoding.UTF8.GetString(output.GetBuffer(), 0, checked((int)output.Length));
    }

    private async Task ValidateRemoteUriAsync(Uri uri, CancellationToken cancellationToken)
    {
        if (NormalizeUrl(uri.AbsoluteUri) is null)
        {
            throw new InvalidOperationException("Blocklist sources and redirects must be public HTTPS URLs.");
        }

        string host = uri.IdnHost.Trim('[', ']');
        if (IPAddress.TryParse(host, out IPAddress? literal))
        {
            if (!IsPublicAddress(literal))
            {
                throw new InvalidOperationException("Blocklist sources cannot target a local or private address.");
            }

            return;
        }

        IReadOnlyList<IPAddress> addresses = await _hostResolver(host, cancellationToken).ConfigureAwait(false);
        if (addresses.Count == 0 || addresses.Any(address => !IsPublicAddress(address)))
        {
            throw new InvalidOperationException("Blocklist source DNS must resolve only to public addresses.");
        }
    }

    private static async Task<IReadOnlyList<IPAddress>> ResolveHostAsync(
        string host,
        CancellationToken cancellationToken) =>
        await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);

    private static bool IsRedirect(HttpStatusCode statusCode) =>
        statusCode is HttpStatusCode.Moved or
            HttpStatusCode.Redirect or
            HttpStatusCode.RedirectMethod or
            HttpStatusCode.TemporaryRedirect or
            HttpStatusCode.PermanentRedirect;

    private static bool IsObviouslyLocalHost(Uri uri)
    {
        string host = uri.IdnHost.Trim('[', ']');
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith(".local", StringComparison.OrdinalIgnoreCase) ||
            !host.Contains('.'))
        {
            return true;
        }

        return IPAddress.TryParse(host, out IPAddress? address) && !IsPublicAddress(address);
    }

    private static bool IsPublicAddress(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            byte[] bytes = address.GetAddressBytes();
            return !address.Equals(IPAddress.IPv6Any) &&
                   !address.Equals(IPAddress.IPv6Loopback) &&
                   !address.IsIPv6LinkLocal &&
                   !address.IsIPv6SiteLocal &&
                   (bytes[0] & 0xFE) != 0xFC && // fc00::/7 unique-local.
                   bytes[0] != 0xFF; // multicast.
        }

        if (address.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        byte[] ipv4 = address.GetAddressBytes();
        return ipv4[0] != 0 &&
               ipv4[0] != 10 &&
               ipv4[0] != 127 &&
               !(ipv4[0] == 100 && ipv4[1] is >= 64 and <= 127) && // carrier-grade NAT.
               !(ipv4[0] == 169 && ipv4[1] == 254) &&
               !(ipv4[0] == 172 && ipv4[1] is >= 16 and <= 31) &&
               !(ipv4[0] == 192 && ipv4[1] == 168) &&
               !(ipv4[0] == 198 && ipv4[1] is 18 or 19) && // benchmark networks.
               ipv4[0] < 224; // multicast and reserved ranges.
    }

    private static string? NormalizeUrl(string input)
    {
        if (!Uri.TryCreate(input?.Trim(), UriKind.Absolute, out Uri? uri) ||
            uri.Scheme != Uri.UriSchemeHttps || string.IsNullOrWhiteSpace(uri.Host) ||
            !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment) ||
            IsObviouslyLocalHost(uri))
        {
            return null;
        }

        return input.Trim();
    }

    private static string? NormalizeQueryName(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return null;
        }

        string candidate = input.Trim().TrimEnd('.').ToLowerInvariant();
        return candidate.Length is > 0 and <= 253 && !candidate.Contains(' ')
            ? candidate
            : null;
    }

    private static string ShortName(string url)
    {
        try
        {
            Uri uri = new(url);
            string name = Path.GetFileName(uri.AbsolutePath);
            return string.IsNullOrEmpty(name) ? uri.Host : name;
        }
        catch
        {
            return url;
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    private sealed class SettingsModel
    {
        public int Version { get; set; } = 1;

        public List<string>? Urls { get; set; } = new();

        public List<string>? CustomDomains { get; set; } = new();

        public List<string>? AllowedDomains { get; set; } = new();

        public FilterMode Mode { get; set; } = FilterMode.Blocklist;
    }

    private sealed class CacheMetadata
    {
        public string? ETag { get; set; }

        public DateTimeOffset? LastModifiedUtc { get; set; }

        public DateTimeOffset FetchedUtc { get; set; }

        public int DomainCount { get; set; }
    }
}
