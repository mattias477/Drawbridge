using System.Net;
using System.Net.Sockets;

namespace Drawbridge.Core;

/// <summary>
/// The engine room: listens for DNS queries on 127.0.0.1:53 AND [::1]:53
/// (Windows uses both), checks each domain against the blocklist, and
/// either relays it upstream or answers "no such domain".
/// </summary>
public class DnsServer
{
    private static readonly IPEndPoint Upstream = new(IPAddress.Parse("8.8.8.8"), 53);

    private readonly BlocklistService _blocklist;
    private readonly List<UdpClient> _listeners = new();
    private CancellationTokenSource? _cts;

    public event Action<string>? Log;

    public bool IsRunning => _cts is { IsCancellationRequested: false };

    public DnsServer(BlocklistService blocklist)
    {
        _blocklist = blocklist;
    }

    public void Start()
    {
        if (IsRunning) return;

        // IPv4 loopback — the main entrance
        _listeners.Add(new UdpClient(new IPEndPoint(IPAddress.Loopback, 53)));

        // IPv6 loopback — so IPv6 DNS can't sneak around the filter
        try
        {
            _listeners.Add(new UdpClient(new IPEndPoint(IPAddress.IPv6Loopback, 53)));
        }
        catch (Exception ex)
        {
            Log?.Invoke($"IPv6 listener unavailable ({ex.Message}) — continuing with IPv4 only");
        }

        _cts = new CancellationTokenSource();
        foreach (UdpClient listener in _listeners)
            _ = ListenLoopAsync(listener, _cts.Token);

        Log?.Invoke("Listening on 127.0.0.1:53 and [::1]:53");
    }

    public void Stop()
    {
        if (!IsRunning) return;

        _cts?.Cancel();
        foreach (UdpClient listener in _listeners)
            listener.Close();
        _listeners.Clear();
        Log?.Invoke("Stopped.");
    }

    private async Task ListenLoopAsync(UdpClient listener, CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                UdpReceiveResult request = await listener.ReceiveAsync(token);
                _ = HandleQueryAsync(listener, request);
            }
        }
        catch (OperationCanceledException) { /* normal shutdown */ }
        catch (ObjectDisposedException) { /* normal shutdown */ }
        catch (Exception ex)
        {
            Log?.Invoke($"Listener error: {ex.Message}");
        }
    }

    private async Task HandleQueryAsync(UdpClient listener, UdpReceiveResult request)
    {
        string domain = DnsPacket.GetQueryDomain(request.Buffer) ?? "(unparsed)";

        try
        {
            // ----- THE CHECKPOINT -----
            if (domain != "(unparsed)" && _blocklist.IsBlocked(domain))
            {
                byte[] refusal = BuildNxDomainResponse(request.Buffer);
                await listener.SendAsync(refusal, refusal.Length,
                                         request.RemoteEndPoint);
                Log?.Invoke($"BLOCKED: {domain}");
                return;
            }

            // Not blocked — relay upstream as before
            using var upstream = new UdpClient();
            await upstream.SendAsync(request.Buffer, request.Buffer.Length, Upstream);

            Task<UdpReceiveResult> responseTask = upstream.ReceiveAsync();
            if (await Task.WhenAny(responseTask, Task.Delay(3000)) == responseTask)
            {
                UdpReceiveResult response = await responseTask;
                await listener.SendAsync(response.Buffer, response.Buffer.Length,
                                         request.RemoteEndPoint);
                Log?.Invoke($"Allowed: {domain}");
            }
            else
            {
                Log?.Invoke($"Upstream timed out for {domain}");
            }
        }
        catch (Exception ex)
        {
            Log?.Invoke($"Query failed for {domain}: {ex.Message}");
        }
    }

    /// <summary>
    /// Turns the query into an NXDOMAIN ("no such domain") response by
    /// flipping two header bits.
    /// </summary>
    private static byte[] BuildNxDomainResponse(byte[] query)
    {
        byte[] response = (byte[])query.Clone();

        response[2] |= 0x80;  // QR bit: this packet is a response
        response[3] = 0x83;   // RA set + RCODE 3 = "Name Error" (NXDOMAIN)

        return response;
    }
}