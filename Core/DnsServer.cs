using System.Net;
using System.Net.Sockets;

namespace Drawbridge.Core;

/// <summary>
/// The engine room, performance edition. Listens for DNS on UDP *and* TCP
/// (browsers retry big, truncated answers over TCP — without this, sites
/// that use large HTTPS records, like YouTube, crawl). Failed lookups
/// retry against a second upstream with a short timeout, and logging is
/// kept quiet so heavy browsing never bottlenecks on the UI.
/// </summary>
public class DnsServer
{
    // Primary and fallback upstream resolvers
    private static readonly IPEndPoint[] Upstreams =
    {
        new(IPAddress.Parse("8.8.8.8"), 53),   // Google
        new(IPAddress.Parse("1.1.1.1"), 53),   // Cloudflare
    };

    private const int UdpTimeoutMs = 1500;   // per upstream attempt
    private const int TcpTimeoutMs = 5000;
    private const int RelayLogEvery = 250;   // summary line frequency

    private readonly BlocklistService _blocklist;
    private readonly List<UdpClient> _udpListeners = new();
    private readonly List<TcpListener> _tcpListeners = new();
    private CancellationTokenSource? _cts;
    private long _relayedCount;

    public event Action<string>? Log;

    public bool IsRunning => _cts is { IsCancellationRequested: false };

    public DnsServer(BlocklistService blocklist)
    {
        _blocklist = blocklist;
    }

    // ---------- lifecycle ----------

    public void Start()
    {
        if (IsRunning) return;

        _cts = new CancellationTokenSource();

        // --- UDP listeners (the normal path) ---
        _udpListeners.Add(new UdpClient(new IPEndPoint(IPAddress.Loopback, 53)));
        try
        {
            _udpListeners.Add(new UdpClient(new IPEndPoint(IPAddress.IPv6Loopback, 53)));
        }
        catch (Exception ex)
        {
            Log?.Invoke($"WARNING: IPv6 UDP listener failed ({ex.Message}). " +
                        "IPv6 lookups will stall — tell me if you see this!");
        }

        // --- TCP listeners (big/truncated responses retry here) ---
        TryStartTcp(IPAddress.Loopback);
        TryStartTcp(IPAddress.IPv6Loopback);

        foreach (UdpClient udp in _udpListeners)
            _ = UdpLoopAsync(udp, _cts.Token);
        foreach (TcpListener tcp in _tcpListeners)
            _ = TcpLoopAsync(tcp, _cts.Token);

        Log?.Invoke($"Listening on 127.0.0.1:53 and [::1]:53 " +
                    $"(UDP x{_udpListeners.Count}, TCP x{_tcpListeners.Count})");
    }

    private void TryStartTcp(IPAddress address)
    {
        try
        {
            var listener = new TcpListener(address, 53);
            listener.Start();
            _tcpListeners.Add(listener);
        }
        catch (Exception ex)
        {
            Log?.Invoke($"WARNING: TCP listener on {address} failed: {ex.Message}");
        }
    }

    public void Stop()
    {
        if (!IsRunning) return;

        _cts?.Cancel();
        foreach (UdpClient udp in _udpListeners) udp.Close();
        foreach (TcpListener tcp in _tcpListeners) tcp.Stop();
        _udpListeners.Clear();
        _tcpListeners.Clear();
        Log?.Invoke("Stopped.");
    }

    // ---------- UDP path ----------

    private async Task UdpLoopAsync(UdpClient listener, CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                UdpReceiveResult request = await listener.ReceiveAsync(token);
                _ = HandleUdpQueryAsync(listener, request);
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
        catch (Exception ex)
        {
            Log?.Invoke($"UDP listener error: {ex.Message}");
        }
    }

    private async Task HandleUdpQueryAsync(UdpClient listener, UdpReceiveResult request)
    {
        string domain = DnsPacket.GetQueryDomain(request.Buffer) ?? "(unparsed)";

        try
        {
            // ----- THE CHECKPOINT -----
            if (domain != "(unparsed)" && _blocklist.IsBlocked(domain))
            {
                byte[] refusal = BuildNxDomainResponse(request.Buffer);
                await listener.SendAsync(refusal, refusal.Length, request.RemoteEndPoint);
                Log?.Invoke($"BLOCKED: {domain}");
                return;
            }

            byte[]? response = await ResolveUdpAsync(request.Buffer);
            if (response is not null)
            {
                await listener.SendAsync(response, response.Length, request.RemoteEndPoint);

                // Quiet success logging: a summary line, not one per lookup.
                // (Per-query UI logging was a real bottleneck under load.)
                long n = Interlocked.Increment(ref _relayedCount);
                if (n % RelayLogEvery == 0)
                    Log?.Invoke($"Relayed {n:N0} lookups so far");
            }
            else
            {
                Log?.Invoke($"All upstreams timed out for {domain}");
            }
        }
        catch (Exception ex)
        {
            Log?.Invoke($"Query failed for {domain}: {ex.Message}");
        }
    }

    /// <summary>Sends the query to each upstream in turn with a short
    /// timeout, returning the first response — packet loss to one server
    /// costs 1.5s, not a dead lookup.</summary>
    private static async Task<byte[]?> ResolveUdpAsync(byte[] query)
    {
        foreach (IPEndPoint upstream in Upstreams)
        {
            try
            {
                using var socket = new UdpClient();
                await socket.SendAsync(query, query.Length, upstream);

                Task<UdpReceiveResult> receive = socket.ReceiveAsync();
                if (await Task.WhenAny(receive, Task.Delay(UdpTimeoutMs)) == receive)
                    return (await receive).Buffer;
            }
            catch
            {
                // fall through to the next upstream
            }
        }
        return null;
    }

    // ---------- TCP path ----------

    private async Task TcpLoopAsync(TcpListener listener, CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                TcpClient client = await listener.AcceptTcpClientAsync(token);
                _ = HandleTcpClientAsync(client);
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
        catch (Exception ex)
        {
            Log?.Invoke($"TCP listener error: {ex.Message}");
        }
    }

    private async Task HandleTcpClientAsync(TcpClient client)
    {
        // DNS-over-TCP frames every message with a 2-byte big-endian length
        try
        {
            using (client)
            {
                client.ReceiveTimeout = TcpTimeoutMs;
                client.SendTimeout = TcpTimeoutMs;
                NetworkStream stream = client.GetStream();

                byte[]? query = await ReadTcpMessageAsync(stream);
                if (query is null) return;

                string domain = DnsPacket.GetQueryDomain(query) ?? "(unparsed)";

                if (domain != "(unparsed)" && _blocklist.IsBlocked(domain))
                {
                    await WriteTcpMessageAsync(stream, BuildNxDomainResponse(query));
                    Log?.Invoke($"BLOCKED (tcp): {domain}");
                    return;
                }

                byte[]? response = await ResolveTcpAsync(query);
                if (response is not null)
                    await WriteTcpMessageAsync(stream, response);
                else
                    Log?.Invoke($"TCP upstreams failed for {domain}");
            }
        }
        catch
        {
            // Individual TCP hiccups are routine; never let them log-spam
        }
    }

    private static async Task<byte[]?> ResolveTcpAsync(byte[] query)
    {
        foreach (IPEndPoint upstream in Upstreams)
        {
            try
            {
                using var client = new TcpClient();
                Task connect = client.ConnectAsync(upstream.Address, upstream.Port);
                if (await Task.WhenAny(connect, Task.Delay(TcpTimeoutMs)) != connect)
                    continue;

                NetworkStream stream = client.GetStream();
                await WriteTcpMessageAsync(stream, query);
                byte[]? response = await ReadTcpMessageAsync(stream);
                if (response is not null)
                    return response;
            }
            catch
            {
                // try the next upstream
            }
        }
        return null;
    }

    private static async Task<byte[]?> ReadTcpMessageAsync(NetworkStream stream)
    {
        byte[] lengthPrefix = new byte[2];
        if (!await ReadExactAsync(stream, lengthPrefix)) return null;

        int length = (lengthPrefix[0] << 8) | lengthPrefix[1];
        if (length == 0 || length > 65535) return null;

        byte[] message = new byte[length];
        return await ReadExactAsync(stream, message) ? message : null;
    }

    private static async Task<bool> ReadExactAsync(NetworkStream stream, byte[] buffer)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(read));
            if (n == 0) return false; // connection closed early
            read += n;
        }
        return true;
    }

    private static async Task WriteTcpMessageAsync(NetworkStream stream, byte[] message)
    {
        byte[] framed = new byte[message.Length + 2];
        framed[0] = (byte)(message.Length >> 8);
        framed[1] = (byte)(message.Length & 0xFF);
        message.CopyTo(framed, 2);
        await stream.WriteAsync(framed);
    }

    // ---------- shared ----------

    /// <summary>NXDOMAIN by flipping two header bits in the query.</summary>
    private static byte[] BuildNxDomainResponse(byte[] query)
    {
        byte[] response = (byte[])query.Clone();
        response[2] |= 0x80;  // QR bit: this is a response
        response[3] = 0x83;   // RA + RCODE 3 ("no such domain")
        return response;
    }
}