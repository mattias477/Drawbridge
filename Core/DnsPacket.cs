using System.Text;

namespace Drawbridge.Core;

/// <summary>
/// Minimal DNS packet reader. Queries encode domain names as
/// length-prefixed labels: [3]www[6]google[3]com[0]
/// </summary>
public static class DnsPacket
{
    /// <summary>
    /// Returns the domain being asked about (e.g. "www.google.com"),
    /// or null if the packet can't be parsed.
    /// </summary>
    public static string? GetQueryDomain(byte[] packet)
    {
        try
        {
            int pos = 12; // skip the fixed 12-byte DNS header
            var labels = new List<string>();

            while (pos < packet.Length)
            {
                byte length = packet[pos++];

                if (length == 0)
                    break;          // zero byte = end of the name

                if (length > 63)
                    return null;    // top bits set = compression pointer;
                                    // plain queries shouldn't contain these

                if (pos + length > packet.Length)
                    return null;    // malformed packet

                labels.Add(Encoding.ASCII.GetString(packet, pos, length));
                pos += length;
            }

            return labels.Count > 0
                ? string.Join('.', labels).ToLowerInvariant()
                : null;
        }
        catch
        {
            return null; // garbage in, null out — never crash the server
        }
    }
}