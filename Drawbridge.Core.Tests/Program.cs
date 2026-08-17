using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Drawbridge.Core;

namespace Drawbridge.Core.Tests;

internal static class Program
{
    private static readonly (string Name, Func<Task> Test)[] Tests =
    [
        ("fresh-install defaults", FreshInstallDefaultsAsync),
        ("Adblock parser", AdblockParserAsync),
        ("specificity ladder", SpecificityLadderAsync),
        ("empty source list persists", EmptySourceListPersistsAsync),
        ("whitelist system essentials", WhitelistSystemEssentialsAsync),
        ("DNS packet parsing and NXDOMAIN", DnsPacketAndNxDomainAsync),
        ("zero-domain cache guard and conditionals", ZeroDomainGuardAsync),
        ("blocklist source SSRF guard", BlocklistSourceSsrfGuardAsync),
        ("concurrent updates serialize", ConcurrentUpdatesSerializeAsync),
        ("legacy cache and metadata migration", LegacyCacheMigrationAsync),
        ("legacy PIN compatibility", LegacyPinCompatibilityAsync),
        ("block history retention and lifetime count", BlockHistoryAsync),
        ("transactional dual-stack UDP/TCP server", DnsServerLifecycleAndPathsAsync),
    ];

    private static async Task<int> Main()
    {
        int failed = 0;
        Console.WriteLine($"Drawbridge.Core dependency-free tests ({Tests.Length})");
        foreach ((string name, Func<Task> test) in Tests)
        {
            try
            {
                await test().ConfigureAwait(false);
                Console.WriteLine($"PASS  {name}");
            }
            catch (Exception ex)
            {
                failed++;
                Console.Error.WriteLine($"FAIL  {name}\n      {ex}");
            }
        }

        Console.WriteLine(failed == 0
            ? $"All {Tests.Length} tests passed."
            : $"{failed} of {Tests.Length} tests failed.");
        return failed == 0 ? 0 : 1;
    }

    private static Task FreshInstallDefaultsAsync()
    {
        using var fixture = new TemporaryDirectory();
        using var service = NewBlocklist(fixture);
        Assert.SequenceEqual(
            [BlocklistService.DefaultNsfwUrl, BlocklistService.DefaultDohUrl],
            service.Urls,
            "Fresh install must include both HaGeZi sources.");
        Assert.True(service.CustomDomains.Contains(BlocklistService.FirefoxDohCanary));
        Assert.True(service.IsBlocked(BlocklistService.FirefoxDohCanary));
        Assert.Equal(FilterMode.Blocklist, service.Mode);
        Assert.True(File.Exists(fixture.Paths.SettingsFile));
        return Task.CompletedTask;
    }

    private static Task AdblockParserAsync()
    {
        const string text = """
            ! title
            ||Example.COM^
             ||sub.example.com^ 
            ||with-options.example^$important
            @@||exception.example^
            ||*.wild.example^
            ||path.example/foo^
            ||nodot^
            0.0.0.0 hosts.example
            """;

        IReadOnlyCollection<string> parsed = BlocklistService.ParseAdblock(text);
        Assert.SetEqual(["example.com", "sub.example.com"], parsed);
        return Task.CompletedTask;
    }

    private static Task SpecificityLadderAsync()
    {
        using var fixture = new TemporaryDirectory();
        using var service = EmptyBlocklist(fixture);
        Assert.True(service.AddCustomDomain("example.com"));
        Assert.True(service.IsBlocked("example.com"));
        Assert.True(service.IsBlocked("child.example.com."));
        Assert.False(service.IsBlocked("unrelated.test"));

        Assert.True(service.AddAllowedDomain("safe.example.com"));
        Assert.False(service.IsBlocked("safe.example.com"));
        Assert.False(service.IsBlocked("deep.safe.example.com"));

        // More-specific block wins over an allowed parent.
        Assert.True(service.AddCustomDomain("evil.safe.example.com"));
        Assert.True(service.IsBlocked("evil.safe.example.com"));

        // At the same level, allowed wins.
        Assert.True(service.AddAllowedDomain("evil.safe.example.com"));
        Assert.False(service.IsBlocked("evil.safe.example.com"));
        return Task.CompletedTask;
    }

    private static Task EmptySourceListPersistsAsync()
    {
        using var fixture = new TemporaryDirectory();
        using (var service = EmptyBlocklist(fixture))
        {
            service.SetMode(FilterMode.Whitelist);
            Assert.Empty(service.Urls);
        }

        using var reloaded = NewBlocklist(fixture);
        Assert.Empty(reloaded.Urls);
        Assert.Equal(FilterMode.Whitelist, reloaded.Mode);
        return Task.CompletedTask;
    }

    private static Task WhitelistSystemEssentialsAsync()
    {
        using var fixture = new TemporaryDirectory();
        using var service = EmptyBlocklist(fixture);
        service.SetMode(FilterMode.Whitelist);
        Assert.True(service.IsBlocked("ordinary.example"));
        foreach (string essential in BlocklistService.SystemEssentials)
        {
            Assert.False(service.IsBlocked(essential), $"{essential} should remain available.");
            Assert.False(service.IsBlocked($"child.{essential}"), $"Subdomains of {essential} should inherit.");
        }

        Assert.True(service.AddAllowedDomain("family.example"));
        Assert.False(service.IsBlocked("photos.family.example"));
        return Task.CompletedTask;
    }

    private static Task DnsPacketAndNxDomainAsync()
    {
        byte[] query = BuildDnsQuery("Blocked.Example", transactionId: 0xBEEF);
        Assert.Equal("blocked.example", DnsPacket.GetQueryDomain(query));
        byte[] response = DnsPacket.BuildNxDomainResponse(query);
        Assert.Equal(query.Length, response.Length);
        Assert.Equal((byte)0xBE, response[0]);
        Assert.Equal((byte)0xEF, response[1]);
        Assert.True((response[2] & 0x80) != 0, "QR bit should be set.");
        Assert.Equal(3, response[3] & 0x0F);
        Assert.True((response[3] & 0x80) != 0, "RA bit should be set.");
        Assert.SequenceEqual(query.AsSpan(4).ToArray(), response.AsSpan(4).ToArray());

        Assert.Null(DnsPacket.GetQueryDomain([0, 1, 2]));
        byte[] truncated = query[..^3];
        Assert.Null(DnsPacket.GetQueryDomain(truncated));
        Assert.Throws<ArgumentException>(() => DnsPacket.BuildNxDomainResponse([1, 2, 3]));
        return Task.CompletedTask;
    }

    private static async Task ZeroDomainGuardAsync()
    {
        using var fixture = new TemporaryDirectory();
        var handler = new SequenceHandler(
            _ => Response(
                HttpStatusCode.OK,
                "||kept.example^\n",
                etag: "\"v1\"",
                lastModified: new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero)),
            _ => Response(HttpStatusCode.OK, "<html>temporary CDN error</html>"),
            _ => new HttpResponseMessage(HttpStatusCode.NotModified));
        using var http = new HttpClient(handler);
        using var service = EmptyBlocklist(fixture, http);
        const string url = "https://lists.test/filter.txt";
        Assert.True(service.AddList(url));

        Assert.Equal(1, await service.CheckForUpdatesAsync());
        Assert.True(service.IsBlocked("kept.example"));
        Assert.Equal(0, await service.CheckForUpdatesAsync());
        Assert.True(service.IsBlocked("kept.example"), "A 200 error page must not replace the cache.");
        Assert.Equal(0, await service.CheckForUpdatesAsync());
        Assert.True(service.IsBlocked("child.kept.example"));

        Assert.Equal(3, handler.Requests.Count);
        Assert.Equal("\"v1\"", handler.Requests[1].ETag);
        Assert.NotNull(handler.Requests[1].IfModifiedSince);

        using var reload = NewBlocklist(fixture, new HttpClient(new SequenceHandler()));
        Assert.True(reload.IsBlocked("kept.example"));
    }

    private static async Task ConcurrentUpdatesSerializeAsync()
    {
        using var fixture = new TemporaryDirectory();
        var handler = new ConcurrencyHandler();
        using var http = new HttpClient(handler);
        using var service = EmptyBlocklist(fixture, http);
        Assert.True(service.AddList("https://lists.test/serialized.txt"));

        await Task.WhenAll(service.CheckForUpdatesAsync(), service.CheckForUpdatesAsync());
        Assert.Equal(1, handler.MaximumConcurrentRequests);
        Assert.True(service.IsBlocked("serialized.example"));
    }

    private static async Task BlocklistSourceSsrfGuardAsync()
    {
        using var fixture = new TemporaryDirectory();
        using (var service = EmptyBlocklist(fixture))
        {
            Assert.False(service.AddList("http://example.com/list.txt"));
            Assert.False(service.AddList("https://localhost/list.txt"));
            Assert.False(service.AddList("https://127.0.0.1/list.txt"));
            Assert.False(service.AddList("https://10.1.2.3/list.txt"));
            Assert.False(service.AddList("https://[::1]/list.txt"));
            Assert.False(service.AddList("https://parent@example.com/list.txt"));
            Assert.True(service.AddList("https://example.com/list.txt"));
        }

        using var privateFixture = new TemporaryDirectory();
        var neverCalled = new SequenceHandler();
        using var privateHttp = new HttpClient(neverCalled);
        using var privateService = EmptyBlocklist(
            privateFixture,
            privateHttp,
            (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Loopback]));
        Assert.True(privateService.AddList("https://public-looking.example/list.txt"));
        Assert.Equal(0, await privateService.CheckForUpdatesAsync());
        Assert.Empty(neverCalled.Requests);

        using var redirectFixture = new TemporaryDirectory();
        var redirectsPrivate = new SequenceHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Redirect);
            response.Headers.Location = new Uri("https://192.168.1.20/list.txt");
            return response;
        });
        using var redirectHttp = new HttpClient(redirectsPrivate);
        using var redirectService = EmptyBlocklist(
            redirectFixture,
            redirectHttp,
            PublicResolver);
        Assert.True(redirectService.AddList("https://public.example/list.txt"));
        Assert.Equal(0, await redirectService.CheckForUpdatesAsync());
        Assert.Equal(1, redirectsPrivate.Requests.Count);
    }

    private static async Task LegacyCacheMigrationAsync()
    {
        using var fixture = new TemporaryDirectory();
        fixture.Paths.EnsureCreated();
        const string url = "https://legacy.test/list.txt";
        File.WriteAllText(
            Path.Combine(fixture.Paths.RootDirectory, "blocklists.json"),
            """
            {"Urls":["https://legacy.test/list.txt"],"CustomDomains":[],"AllowedDomains":[],"Mode":"Blocklist"}
            """);

        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(url));
        string oldCache = Path.Combine(
            fixture.Paths.CacheDirectory,
            $"{Convert.ToHexString(hash)[..16].ToLowerInvariant()}.txt");
        File.WriteAllText(oldCache, "||legacy.example^\n");
        File.WriteAllText(
            Path.Combine(fixture.Paths.CacheDirectory, "meta.json"),
            """
            {"https://legacy.test/list.txt":{"Etag":"\"legacy-etag\"","LastModified":"Fri, 03 Jan 2025 00:00:00 GMT","FetchedUtc":"2025-01-03T00:00:00Z"}}
            """);
        // A running fresh v2 service creates this before first-run migration copies meta.json.
        File.WriteAllText(fixture.Paths.CacheMetadataFile, "{}");

        var handler = new SequenceHandler(_ => new HttpResponseMessage(HttpStatusCode.NotModified));
        using var http = new HttpClient(handler);
        using var service = NewBlocklist(fixture, http);
        Assert.True(service.IsBlocked("legacy.example"));
        Assert.True(File.Exists(fixture.Paths.SettingsFile), "Legacy settings should upgrade to settings.json.");
        Assert.False(File.Exists(oldCache), "Legacy cache should be atomically upgraded.");
        Assert.Equal(0, await service.CheckForUpdatesAsync());
        Assert.Equal("\"legacy-etag\"", handler.Requests.Single().ETag);
        Assert.NotNull(handler.Requests.Single().IfModifiedSince);
        Assert.True(service.IsBlocked("legacy.example"));
    }

    private static Task LegacyPinCompatibilityAsync()
    {
        using var fixture = new TemporaryDirectory();
        fixture.Paths.EnsureCreated();
        byte[] salt = Enumerable.Range(1, 16).Select(value => (byte)value).ToArray();
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
            "2468", salt, 100_000, HashAlgorithmName.SHA256, 32);
        string legacyRecord = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["salt"] = Convert.ToBase64String(salt),
            ["HASH"] = Convert.ToBase64String(hash),
        });
        File.WriteAllText(fixture.Paths.PinFile, legacyRecord);

        var pins = new PinService(fixture.Paths);
        Assert.True(pins.HasPin);
        Assert.True(pins.Verify("2468"));
        Assert.False(pins.Verify("2469"));
        pins.SetPin("1357");
        Assert.False(pins.Verify("2468"));
        Assert.True(pins.Verify("1357"));
        Assert.True(pins.RemovePin());
        Assert.False(pins.HasPin);
        pins.ImportLegacyRecord(legacyRecord);
        Assert.True(pins.Verify("2468"));
        return Task.CompletedTask;
    }

    private static Task BlockHistoryAsync()
    {
        using var fixture = new TemporaryDirectory();
        fixture.Paths.EnsureCreated();
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 8, 17, 12, 30, 0, TimeSpan.Zero));
        DateTime expiredDay = clock.GetUtcNow().UtcDateTime.Date.AddDays(-90);
        string expiredFile = Path.Combine(
            fixture.Paths.LogsDirectory, $"blocks-{expiredDay:yyyy-MM-dd}.log");
        File.WriteAllText(expiredFile, "01:02:03\told.example\n");
        File.WriteAllText(
            Path.Combine(fixture.Paths.LogsDirectory, "block-stats.json"),
            "{\"TotalRecorded\":10}");

        var history = new BlockLogService(fixture.Paths, clock);
        history.Load();
        Assert.False(File.Exists(expiredFile));
        Assert.Equal(10L, history.AllTimeBlocked);
        history.Record("bad\tname.example\n");
        Assert.Equal(1, history.TodayBlocked);
        Assert.Equal(11L, history.AllTimeBlocked);
        Assert.Equal("bad name.example", history.Recent(1).Single().Domain);
        Assert.Equal(14, history.Daily(14).Count);

        var reloaded = new BlockLogService(fixture.Paths, clock);
        reloaded.Load();
        Assert.Equal(1, reloaded.TodayBlocked);
        Assert.Equal(11L, reloaded.AllTimeBlocked);
        Assert.Equal(clock.GetUtcNow().UtcDateTime.Date, reloaded.Recent(1).Single().Timestamp.Date);
        return Task.CompletedTask;
    }

    private static async Task DnsServerLifecycleAndPathsAsync()
    {
        using var fixture = new TemporaryDirectory();
        using var blocklist = NewBlocklist(fixture);
        int port;
        var blocker = new TcpListener(IPAddress.Loopback, 0);
        blocker.Start();
        port = ((IPEndPoint)blocker.LocalEndpoint).Port;

        await using var server = new DnsServer(blocklist, new DnsServerOptions
        {
            ListenPort = port,
            Upstreams = [new IPEndPoint(IPAddress.Loopback, 9)],
            UpstreamTimeout = TimeSpan.FromMilliseconds(100),
            TcpClientIdleTimeout = TimeSpan.FromSeconds(2),
            MaxConcurrentQueries = 16,
        });

        Assert.Throws<SocketException>(() => server.Start());
        Assert.False(server.IsRunning, "Failed transactional bind must leave IsRunning false.");
        blocker.Stop();

        server.Start();
        Assert.True(server.IsRunning);
        byte[] query = BuildDnsQuery(BlocklistService.FirefoxDohCanary, 0x1234);

        using (var udp = new UdpClient(AddressFamily.InterNetwork))
        {
            await udp.SendAsync(query, new IPEndPoint(IPAddress.Loopback, port));
            UdpReceiveResult result = await udp.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(2));
            Assert.Equal(3, result.Buffer[3] & 0x0F);
            Assert.Equal((byte)0x12, result.Buffer[0]);
            Assert.Equal((byte)0x34, result.Buffer[1]);
        }

        using (var tcp = new TcpClient(AddressFamily.InterNetwork))
        {
            await tcp.ConnectAsync(IPAddress.Loopback, port);
            NetworkStream stream = tcp.GetStream();
            byte[] framed = new byte[query.Length + 2];
            framed[0] = (byte)(query.Length >> 8);
            framed[1] = (byte)query.Length;
            query.CopyTo(framed, 2);
            await stream.WriteAsync(framed);
            byte[] prefix = new byte[2];
            await ReadExactlyAsync(stream, prefix).WaitAsync(TimeSpan.FromSeconds(2));
            int responseLength = (prefix[0] << 8) | prefix[1];
            byte[] response = new byte[responseLength];
            await ReadExactlyAsync(stream, response).WaitAsync(TimeSpan.FromSeconds(2));
            Assert.Equal(3, response[3] & 0x0F);
            Assert.Equal((byte)0x12, response[0]);
            Assert.Equal((byte)0x34, response[1]);
        }

        await server.StopAsync();
        Assert.False(server.IsRunning);
    }

    private static async Task ReadExactlyAsync(NetworkStream stream, Memory<byte> destination)
    {
        int offset = 0;
        while (offset < destination.Length)
        {
            int read = await stream.ReadAsync(destination[offset..]);
            if (read == 0)
            {
                throw new EndOfStreamException();
            }

            offset += read;
        }
    }

    private static BlocklistService NewBlocklist(
        TemporaryDirectory fixture,
        HttpClient? client = null,
        Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>>? resolver = null) =>
        new(fixture.Paths, client, resolver ?? PublicResolver);

    private static BlocklistService EmptyBlocklist(
        TemporaryDirectory fixture,
        HttpClient? client = null,
        Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>>? resolver = null)
    {
        var service = NewBlocklist(fixture, client, resolver);
        foreach (string url in service.Urls.ToArray())
        {
            service.RemoveList(url);
        }

        foreach (string domain in service.CustomDomains.ToArray())
        {
            service.RemoveCustomDomain(domain);
        }

        foreach (string domain in service.AllowedDomains.ToArray())
        {
            service.RemoveAllowedDomain(domain);
        }

        service.SetMode(FilterMode.Blocklist);
        return service;
    }

    private static Task<IReadOnlyList<IPAddress>> PublicResolver(
        string host,
        CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Parse("93.184.216.34")]);

    private static byte[] BuildDnsQuery(string domain, ushort transactionId)
    {
        using var stream = new MemoryStream();
        stream.WriteByte((byte)(transactionId >> 8));
        stream.WriteByte((byte)transactionId);
        stream.Write([0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        foreach (string label in domain.Split('.'))
        {
            byte[] bytes = Encoding.ASCII.GetBytes(label);
            stream.WriteByte((byte)bytes.Length);
            stream.Write(bytes);
        }

        stream.Write([0x00, 0x00, 0x01, 0x00, 0x01]);
        return stream.ToArray();
    }

    private static HttpResponseMessage Response(
        HttpStatusCode status,
        string body,
        string? etag = null,
        DateTimeOffset? lastModified = null)
    {
        var response = new HttpResponseMessage(status)
        {
            Content = new StringContent(body, Encoding.UTF8),
        };
        if (etag is not null)
        {
            response.Headers.ETag = EntityTagHeaderValue.Parse(etag);
        }

        response.Content.Headers.LastModified = lastModified;
        return response;
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            string root = Path.Combine(
                Path.GetTempPath(), "Drawbridge.Core.Tests", Guid.NewGuid().ToString("N"));
            Paths = new DrawbridgePaths(root);
        }

        public DrawbridgePaths Paths { get; }

        public void Dispose()
        {
            try { Directory.Delete(Paths.RootDirectory, recursive: true); } catch { }
        }
    }

    private sealed record RequestObservation(string? ETag, DateTimeOffset? IfModifiedSince);

    private sealed class SequenceHandler : HttpMessageHandler
    {
        private readonly Queue<Func<HttpRequestMessage, HttpResponseMessage>> _responses;

        public SequenceHandler(params Func<HttpRequestMessage, HttpResponseMessage>[] responses)
        {
            _responses = new Queue<Func<HttpRequestMessage, HttpResponseMessage>>(responses);
        }

        public List<RequestObservation> Requests { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests.Add(new RequestObservation(
                request.Headers.IfNoneMatch.FirstOrDefault()?.ToString(),
                request.Headers.IfModifiedSince));
            if (_responses.Count == 0)
            {
                throw new InvalidOperationException("No queued HTTP response.");
            }

            return Task.FromResult(_responses.Dequeue()(request));
        }
    }

    private sealed class ConcurrencyHandler : HttpMessageHandler
    {
        private int _active;
        private int _maximum;

        public int MaximumConcurrentRequests => Volatile.Read(ref _maximum);

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            int active = Interlocked.Increment(ref _active);
            int observed;
            do
            {
                observed = Volatile.Read(ref _maximum);
            }
            while (active > observed &&
                   Interlocked.CompareExchange(ref _maximum, active, observed) != observed);

            try
            {
                await Task.Delay(75, cancellationToken);
                return Response(HttpStatusCode.OK, "||serialized.example^\n");
            }
            finally
            {
                Interlocked.Decrement(ref _active);
            }
        }
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private readonly DateTimeOffset _utcNow;

        public ManualTimeProvider(DateTimeOffset utcNow)
        {
            _utcNow = utcNow.ToUniversalTime();
        }

        public override TimeZoneInfo LocalTimeZone => TimeZoneInfo.Utc;

        public override DateTimeOffset GetUtcNow() => _utcNow;
    }

    private static class Assert
    {
        public static void True(bool condition, string? message = null)
        {
            if (!condition)
            {
                throw new TestFailureException(message ?? "Expected true, got false.");
            }
        }

        public static void False(bool condition, string? message = null) =>
            True(!condition, message ?? "Expected false, got true.");

        public static void Null(object? value)
        {
            if (value is not null)
            {
                throw new TestFailureException($"Expected null, got {value}.");
            }
        }

        public static void NotNull(object? value)
        {
            if (value is null)
            {
                throw new TestFailureException("Expected a non-null value.");
            }
        }

        public static void Empty<T>(IEnumerable<T> values)
        {
            if (values.Any())
            {
                throw new TestFailureException("Expected an empty sequence.");
            }
        }

        public static void Equal<T>(T expected, T actual, string? message = null)
        {
            if (!EqualityComparer<T>.Default.Equals(expected, actual))
            {
                throw new TestFailureException(message ?? $"Expected {expected}, got {actual}.");
            }
        }

        public static void SequenceEqual<T>(
            IEnumerable<T> expected,
            IEnumerable<T> actual,
            string? message = null)
        {
            if (!expected.SequenceEqual(actual))
            {
                throw new TestFailureException(message ??
                    $"Sequences differ. Expected [{string.Join(", ", expected)}], got [{string.Join(", ", actual)}].");
            }
        }

        public static void SetEqual<T>(IEnumerable<T> expected, IEnumerable<T> actual)
        {
            if (!new HashSet<T>(expected).SetEquals(actual))
            {
                throw new TestFailureException("Sets differ.");
            }
        }

        public static void Throws<TException>(Action action)
            where TException : Exception
        {
            try
            {
                action();
            }
            catch (TException)
            {
                return;
            }
            catch (Exception ex)
            {
                throw new TestFailureException(
                    $"Expected {typeof(TException).Name}, got {ex.GetType().Name}.");
            }

            throw new TestFailureException($"Expected {typeof(TException).Name}, but no exception was thrown.");
        }
    }

    private sealed class TestFailureException : Exception
    {
        public TestFailureException(string message)
            : base(message)
        {
        }
    }
}
