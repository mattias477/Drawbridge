using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace Drawbridge.Core;

/// <summary>Configures DNS listener endpoints, upstreams, and failure timeouts.</summary>
public sealed class DnsServerOptions
{
    /// <summary>Gets or sets the UDP and TCP loopback listener port.</summary>
    public int ListenPort { get; set; } = 53;

    /// <summary>Gets or sets upstream resolvers, in failover order.</summary>
    public IReadOnlyList<IPEndPoint> Upstreams { get; set; } =
    [
        new IPEndPoint(IPAddress.Parse("8.8.8.8"), 53),
        new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53),
    ];

    /// <summary>Gets or sets the complete per-upstream attempt timeout.</summary>
    public TimeSpan UpstreamTimeout { get; set; } = TimeSpan.FromMilliseconds(1500);

    /// <summary>Gets or sets the idle timeout for a local TCP DNS client.</summary>
    public TimeSpan TcpClientIdleTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>Gets or sets the delay after a recovered listener exception.</summary>
    public TimeSpan ListenerRecoveryDelay { get; set; } = TimeSpan.FromMilliseconds(100);

    /// <summary>Gets or sets the maximum number of queries processed concurrently.</summary>
    public int MaxConcurrentQueries { get; set; } = 512;
}

/// <summary>
/// Hosts unkillable IPv4/IPv6 UDP and TCP DNS loops, filters names locally, and relays raw
/// messages to ordered upstream resolvers.
/// </summary>
public sealed class DnsServer : IDisposable, IAsyncDisposable
{
    private const int SioUdpConnectionReset = unchecked((int)0x9800000C);
    private const int RelayLogInterval = 250;
    private const int MaximumDnsMessageLength = ushort.MaxValue;

    private readonly object _lifecycleLock = new();
    private readonly BlocklistService _blocklist;
    private readonly int _listenPort;
    private readonly IPEndPoint[] _upstreams;
    private readonly TimeSpan _upstreamTimeout;
    private readonly TimeSpan _tcpClientIdleTimeout;
    private readonly TimeSpan _listenerRecoveryDelay;
    private readonly SemaphoreSlim _querySlots;
    private readonly ConcurrentDictionary<long, Task> _activeHandlers = new();
    private readonly List<Socket> _udpListeners = new();
    private readonly List<TcpListener> _tcpListeners = new();
    private readonly List<Task> _listenerTasks = new();
    private CancellationTokenSource? _cancellation;
    private long _handlerSequence;
    private long _relayCount;
    private long _connectionResetCount;
    private long _overloadDropCount;
    private bool _disposed;

    /// <summary>Creates a DNS server using the standard loopback endpoints and upstreams.</summary>
    /// <param name="blocklist">The live filter decision service.</param>
    /// <param name="options">Optional server configuration.</param>
    public DnsServer(BlocklistService blocklist, DnsServerOptions? options = null)
    {
        _blocklist = blocklist ?? throw new ArgumentNullException(nameof(blocklist));
        options ??= new DnsServerOptions();

        if (options.ListenPort is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "ListenPort must be between 1 and 65535.");
        }

        if (options.Upstreams is null || options.Upstreams.Count == 0 ||
            options.Upstreams.Any(endpoint => endpoint is null))
        {
            throw new ArgumentException("At least one upstream endpoint is required.", nameof(options));
        }

        if (options.UpstreamTimeout <= TimeSpan.Zero ||
            options.TcpClientIdleTimeout <= TimeSpan.Zero ||
            options.ListenerRecoveryDelay < TimeSpan.Zero ||
            options.MaxConcurrentQueries <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Timeouts and concurrency limits are invalid.");
        }

        _listenPort = options.ListenPort;
        _upstreams = options.Upstreams
            .Select(endpoint => new IPEndPoint(endpoint.Address, endpoint.Port))
            .ToArray();
        _upstreamTimeout = options.UpstreamTimeout;
        _tcpClientIdleTimeout = options.TcpClientIdleTimeout;
        _listenerRecoveryDelay = options.ListenerRecoveryDelay;
        _querySlots = new SemaphoreSlim(options.MaxConcurrentQueries, options.MaxConcurrentQueries);
    }

    /// <summary>Raised for lifecycle events, blocks, summaries, and recovered errors.</summary>
    public event Action<string>? Log;

    /// <summary>Raised with the parsed hostname for every locally blocked lookup.</summary>
    public event Action<string>? Blocked;

    /// <summary>Gets whether all listener loops have been started and not stopped.</summary>
    public bool IsRunning
    {
        get
        {
            lock (_lifecycleLock)
            {
                return _cancellation is { IsCancellationRequested: false };
            }
        }
    }

    /// <summary>
    /// Atomically binds UDP and TCP on both 127.0.0.1 and ::1. If any required bind fails,
    /// all binds are rolled back and the exception is propagated for the host's retry loop.
    /// </summary>
    public void Start()
    {
        ThrowIfDisposed();
        lock (_lifecycleLock)
        {
            if (_cancellation is { IsCancellationRequested: false })
            {
                return;
            }

            var cancellation = new CancellationTokenSource();
            var udpListeners = new List<Socket>();
            var tcpListeners = new List<TcpListener>();
            try
            {
                udpListeners.Add(CreateUdpListener(IPAddress.Loopback));
                udpListeners.Add(CreateUdpListener(IPAddress.IPv6Loopback));
                tcpListeners.Add(CreateTcpListener(IPAddress.Loopback));
                tcpListeners.Add(CreateTcpListener(IPAddress.IPv6Loopback));

                _cancellation = cancellation;
                _udpListeners.AddRange(udpListeners);
                _tcpListeners.AddRange(tcpListeners);

                foreach (Socket listener in _udpListeners)
                {
                    _listenerTasks.Add(UdpListenLoopAsync(listener, cancellation.Token));
                }

                foreach (TcpListener listener in _tcpListeners)
                {
                    _listenerTasks.Add(TcpAcceptLoopAsync(listener, cancellation.Token));
                }
            }
            catch
            {
                cancellation.Cancel();
                foreach (Socket listener in udpListeners)
                {
                    listener.Dispose();
                }

                foreach (TcpListener listener in tcpListeners)
                {
                    listener.Stop();
                }

                cancellation.Dispose();
                throw;
            }
        }

        Log?.Invoke($"DNS listening on 127.0.0.1:{_listenPort} and [::1]:{_listenPort} over UDP and TCP.");
    }

    /// <summary>Stops listeners and waits for their in-flight query handlers to settle.</summary>
    public void Stop() => StopAsync().AsTask().GetAwaiter().GetResult();

    /// <summary>Stops listeners and asynchronously waits for in-flight query handlers.</summary>
    public async ValueTask StopAsync()
    {
        CancellationTokenSource? cancellation;
        Task[] listenerTasks;
        lock (_lifecycleLock)
        {
            cancellation = _cancellation;
            if (cancellation is null)
            {
                return;
            }

            _cancellation = null;
            cancellation.Cancel();
            foreach (Socket listener in _udpListeners)
            {
                try { listener.Dispose(); } catch { }
            }

            foreach (TcpListener listener in _tcpListeners)
            {
                try { listener.Stop(); } catch { }
            }

            _udpListeners.Clear();
            _tcpListeners.Clear();
            listenerTasks = _listenerTasks.ToArray();
            _listenerTasks.Clear();
        }

        await IgnoreFailuresAsync(listenerTasks).ConfigureAwait(false);
        await IgnoreFailuresAsync(_activeHandlers.Values.ToArray()).ConfigureAwait(false);
        cancellation.Dispose();
        Log?.Invoke("DNS listeners stopped.");
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        Stop();
        _disposed = true;
        _querySlots.Dispose();
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        await StopAsync().ConfigureAwait(false);
        _disposed = true;
        _querySlots.Dispose();
        GC.SuppressFinalize(this);
    }

    private Socket CreateUdpListener(IPAddress address)
    {
        var socket = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                socket.DualMode = false;
            }

            DisableUdpConnectionReset(socket);
            socket.Bind(new IPEndPoint(address, _listenPort));
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private TcpListener CreateTcpListener(IPAddress address)
    {
        var listener = new TcpListener(address, _listenPort);
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            listener.Server.DualMode = false;
        }

        listener.Start();
        return listener;
    }

    private async Task UdpListenLoopAsync(Socket listener, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[MaximumDnsMessageLength];
        EndPoint anyRemote = listener.AddressFamily == AddressFamily.InterNetwork
            ? new IPEndPoint(IPAddress.Any, 0)
            : new IPEndPoint(IPAddress.IPv6Any, 0);

        // Each receive is guarded inside the while. No packet or routine socket error can
        // escape and permanently end this listener.
        while (!cancellationToken.IsCancellationRequested)
        {
            SocketReceiveFromResult received;
            try
            {
                received = await listener.ReceiveFromAsync(
                    buffer, SocketFlags.None, anyRemote, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
            {
                if (Interlocked.Increment(ref _connectionResetCount) == 1)
                {
                    Log?.Invoke("Ignored a leaked UDP ICMP connection reset; listeners remain healthy.");
                }

                continue;
            }
            catch (Exception ex)
            {
                Log?.Invoke($"UDP receive error (recovered): {ex.Message}");
                if (!await DelayAfterListenerErrorAsync(cancellationToken).ConfigureAwait(false))
                {
                    return;
                }

                continue;
            }

            if (!_querySlots.Wait(0))
            {
                if (Interlocked.Increment(ref _overloadDropCount) == 1)
                {
                    Log?.Invoke("DNS concurrency limit reached; excess packets are being dropped until capacity returns.");
                }

                continue;
            }

            byte[] query = buffer.AsSpan(0, received.ReceivedBytes).ToArray();
            TrackHandler(HandleUdpQueryAsync(
                listener, query, received.RemoteEndPoint, cancellationToken, releaseSlot: true));
        }
    }

    private async Task HandleUdpQueryAsync(
        Socket listener,
        byte[] query,
        EndPoint remoteEndPoint,
        CancellationToken cancellationToken,
        bool releaseSlot)
    {
        string domain = DnsPacket.GetQueryDomain(query) ?? "(unparsed)";
        try
        {
            if (domain != "(unparsed)" && _blocklist.IsBlocked(domain))
            {
                byte[] response = DnsPacket.BuildNxDomainResponse(query);
                await listener.SendToAsync(
                    response, SocketFlags.None, remoteEndPoint, cancellationToken).ConfigureAwait(false);
                NotifyBlocked(domain, isTcp: false);
                return;
            }

            byte[]? responseFromUpstream = await ResolveUdpAsync(query, cancellationToken).ConfigureAwait(false);
            if (responseFromUpstream is null)
            {
                Log?.Invoke($"All upstream DNS servers timed out for {domain}.");
                return;
            }

            await listener.SendToAsync(
                responseFromUpstream, SocketFlags.None, remoteEndPoint, cancellationToken).ConfigureAwait(false);
            NotifyRelayed();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (ObjectDisposedException)
        {
        }
        catch (Exception ex)
        {
            Log?.Invoke($"UDP query failed for {domain}: {ex.Message}");
        }
        finally
        {
            if (releaseSlot)
            {
                _querySlots.Release();
            }
        }
    }

    private async Task<byte[]?> ResolveUdpAsync(byte[] query, CancellationToken serverCancellation)
    {
        foreach (IPEndPoint upstream in _upstreams)
        {
            using var socket = new Socket(upstream.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                DisableUdpConnectionReset(socket);
                using var attempt = CancellationTokenSource.CreateLinkedTokenSource(serverCancellation);
                attempt.CancelAfter(_upstreamTimeout);
                await socket.ConnectAsync(upstream, attempt.Token).ConfigureAwait(false);
                await socket.SendAsync(query, SocketFlags.None, attempt.Token).ConfigureAwait(false);

                byte[] response = new byte[MaximumDnsMessageLength];
                int length = await socket.ReceiveAsync(
                    response, SocketFlags.None, attempt.Token).ConfigureAwait(false);
                if (length >= 2 && query.Length >= 2 &&
                    response[0] == query[0] && response[1] == query[1])
                {
                    return response.AsSpan(0, length).ToArray();
                }
            }
            catch (OperationCanceledException) when (serverCancellation.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                // Timeout, ICMP error, and malformed upstream behavior all fail over.
            }
        }

        return null;
    }

    private async Task TcpAcceptLoopAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        // Like UDP, accept errors are caught inside the while and cannot kill this listener.
        while (!cancellationToken.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException ex) when (
                cancellationToken.IsCancellationRequested || ex.SocketErrorCode == SocketError.OperationAborted)
            {
                return;
            }
            catch (Exception ex)
            {
                Log?.Invoke($"TCP accept error (recovered): {ex.Message}");
                if (!await DelayAfterListenerErrorAsync(cancellationToken).ConfigureAwait(false))
                {
                    return;
                }

                continue;
            }

            if (!_querySlots.Wait(0))
            {
                client.Dispose();
                if (Interlocked.Increment(ref _overloadDropCount) == 1)
                {
                    Log?.Invoke("DNS concurrency limit reached; excess connections are being dropped until capacity returns.");
                }

                continue;
            }

            TrackHandler(HandleTcpClientAsync(client, cancellationToken));
        }
    }

    private async Task HandleTcpClientAsync(TcpClient client, CancellationToken serverCancellation)
    {
        try
        {
            using (client)
            {
                client.NoDelay = true;
                NetworkStream stream = client.GetStream();
                while (!serverCancellation.IsCancellationRequested)
                {
                    byte[]? query = await ReadTcpMessageAsync(
                        stream, _tcpClientIdleTimeout, serverCancellation).ConfigureAwait(false);
                    if (query is null)
                    {
                        return;
                    }

                    string domain = DnsPacket.GetQueryDomain(query) ?? "(unparsed)";
                    byte[]? response;
                    if (domain != "(unparsed)" && _blocklist.IsBlocked(domain))
                    {
                        response = DnsPacket.BuildNxDomainResponse(query);
                        NotifyBlocked(domain, isTcp: true);
                    }
                    else
                    {
                        response = await ResolveTcpAsync(query, serverCancellation).ConfigureAwait(false);
                        if (response is null)
                        {
                            Log?.Invoke($"All upstream TCP DNS servers timed out for {domain}.");
                            return;
                        }

                        NotifyRelayed();
                    }

                    await WriteTcpMessageAsync(stream, response, serverCancellation).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Server shutdown and idle clients are routine.
        }
        catch (IOException)
        {
            // Clients routinely disconnect without a DNS-level close handshake.
        }
        catch (SocketException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
        catch (Exception ex)
        {
            Log?.Invoke($"TCP query error (recovered): {ex.Message}");
        }
        finally
        {
            _querySlots.Release();
        }
    }

    private async Task<byte[]?> ResolveTcpAsync(byte[] query, CancellationToken serverCancellation)
    {
        foreach (IPEndPoint upstream in _upstreams)
        {
            using var client = new TcpClient(upstream.AddressFamily);
            try
            {
                using var attempt = CancellationTokenSource.CreateLinkedTokenSource(serverCancellation);
                attempt.CancelAfter(_upstreamTimeout);
                await client.ConnectAsync(upstream.Address, upstream.Port, attempt.Token).ConfigureAwait(false);
                NetworkStream stream = client.GetStream();
                await WriteTcpMessageAsync(stream, query, attempt.Token).ConfigureAwait(false);
                byte[]? response = await ReadTcpMessageAsync(
                    stream, _upstreamTimeout, attempt.Token).ConfigureAwait(false);
                if (response is { Length: >= 2 } && query.Length >= 2 &&
                    response[0] == query[0] && response[1] == query[1])
                {
                    return response;
                }
            }
            catch (OperationCanceledException) when (serverCancellation.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                // Try the next upstream after any per-upstream failure.
            }
        }

        return null;
    }

    private static async Task<byte[]?> ReadTcpMessageAsync(
        NetworkStream stream,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var idle = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        idle.CancelAfter(timeout);
        byte[] prefix = new byte[2];
        if (!await ReadExactlyOrEofAsync(stream, prefix, idle.Token).ConfigureAwait(false))
        {
            return null;
        }

        int length = (prefix[0] << 8) | prefix[1];
        if (length == 0)
        {
            return null;
        }

        byte[] message = new byte[length];
        return await ReadExactlyOrEofAsync(stream, message, idle.Token).ConfigureAwait(false)
            ? message
            : null;
    }

    private static async Task<bool> ReadExactlyOrEofAsync(
        NetworkStream stream,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < destination.Length)
        {
            int read = await stream.ReadAsync(destination[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return false;
            }

            offset += read;
        }

        return true;
    }

    private static async Task WriteTcpMessageAsync(
        NetworkStream stream,
        ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken)
    {
        if (message.Length is < 1 or > MaximumDnsMessageLength)
        {
            throw new InvalidDataException("DNS-over-TCP message length is invalid.");
        }

        byte[] prefix = [(byte)(message.Length >> 8), (byte)message.Length];
        await stream.WriteAsync(prefix, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(message, cancellationToken).ConfigureAwait(false);
    }

    private void DisableUdpConnectionReset(Socket socket)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            // BOOL FALSE as a four-byte native value. This is applied to every UDP listener
            // and every short-lived UDP upstream socket before receiving from it.
            socket.IOControl(
                (IOControlCode)SioUdpConnectionReset,
                [0, 0, 0, 0],
                optionOutValue: null);
        }
        catch (Exception ex)
        {
            // The receive loop still catches ConnectionReset, but surface this once so a host
            // can diagnose a Winsock stack that rejected the mandatory hardening call.
            if (Interlocked.Increment(ref _connectionResetCount) == 1)
            {
                Log?.Invoke($"SIO_UDP_CONNRESET could not be disabled; listener recovery remains active: {ex.Message}");
            }
        }
    }

    private void NotifyBlocked(string domain, bool isTcp)
    {
        Log?.Invoke($"BLOCKED{(isTcp ? " (TCP)" : string.Empty)}: {domain}");
        Blocked?.Invoke(domain);
    }

    private void NotifyRelayed()
    {
        long count = Interlocked.Increment(ref _relayCount);
        if (count % RelayLogInterval == 0)
        {
            Log?.Invoke($"Relayed {count:N0} DNS lookups.");
        }
    }

    private async Task<bool> DelayAfterListenerErrorAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(_listenerRecoveryDelay, cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    private void TrackHandler(Task task)
    {
        long id = Interlocked.Increment(ref _handlerSequence);
        _activeHandlers[id] = task;
        _ = ObserveHandlerAsync(id, task);
    }

    private async Task ObserveHandlerAsync(long id, Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Log?.Invoke($"DNS handler error (recovered): {ex.Message}");
        }
        finally
        {
            _activeHandlers.TryRemove(id, out _);
        }
    }

    private static async Task IgnoreFailuresAsync(IEnumerable<Task> tasks)
    {
        try
        {
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        catch
        {
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}
