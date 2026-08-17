using System.Buffers.Binary;
using System.Text;

namespace Drawbridge.Core;

/// <summary>Provides bounded parsing and NXDOMAIN construction for raw DNS messages.</summary>
public static class DnsPacket
{
    private const int HeaderLength = 12;

    /// <summary>Gets the first question name, or <see langword="null"/> for a malformed packet.</summary>
    /// <param name="packet">A complete unframed DNS message.</param>
    public static string? GetQueryDomain(byte[] packet)
    {
        ArgumentNullException.ThrowIfNull(packet);
        return GetQueryDomain(packet.AsSpan());
    }

    /// <summary>Gets the first question name, or <see langword="null"/> for a malformed packet.</summary>
    /// <param name="packet">A complete unframed DNS message.</param>
    public static string? GetQueryDomain(ReadOnlySpan<byte> packet) =>
        TryGetQueryDomain(packet, out string? domain) ? domain : null;

    /// <summary>Attempts to parse the first DNS question name without throwing.</summary>
    /// <param name="packet">A complete unframed DNS message.</param>
    /// <param name="domain">Receives the lowercase, non-root DNS name.</param>
    public static bool TryGetQueryDomain(ReadOnlySpan<byte> packet, out string? domain)
    {
        domain = null;
        if (packet.Length < HeaderLength ||
            BinaryPrimitives.ReadUInt16BigEndian(packet[4..6]) == 0)
        {
            return false;
        }

        if (!TryReadName(packet, HeaderLength, out string? name, out int nextOffset) ||
            string.IsNullOrEmpty(name) || nextOffset > packet.Length - 4)
        {
            return false;
        }

        // A syntactically complete question has QTYPE and QCLASS after QNAME.
        domain = name;
        return true;
    }

    /// <summary>
    /// Echoes a DNS query as a recursive-capable NXDOMAIN response, preserving the transaction,
    /// question, and any EDNS options while setting QR and response code 3.
    /// </summary>
    /// <param name="query">A complete unframed DNS query.</param>
    /// <returns>A newly allocated DNS response.</returns>
    /// <exception cref="ArgumentException">The message is shorter than a DNS header.</exception>
    public static byte[] BuildNxDomainResponse(ReadOnlySpan<byte> query)
    {
        if (query.Length < HeaderLength)
        {
            throw new ArgumentException("A DNS message must contain a 12-byte header.", nameof(query));
        }

        byte[] response = query.ToArray();
        response[2] |= 0x80; // QR: response.
        response[3] = (byte)((response[3] & 0x70) | 0x83); // RA plus RCODE=NXDOMAIN.
        return response;
    }

    private static bool TryReadName(
        ReadOnlySpan<byte> packet,
        int startOffset,
        out string? name,
        out int nextOffset)
    {
        name = null;
        nextOffset = startOffset;
        int offset = startOffset;
        int expandedLength = 0;
        int jumpCount = 0;
        bool jumped = false;
        var visitedPointers = new HashSet<int>();
        var labels = new List<string>();

        while (true)
        {
            if ((uint)offset >= (uint)packet.Length)
            {
                return false;
            }

            byte marker = packet[offset];
            if ((marker & 0xC0) == 0xC0)
            {
                if (offset > packet.Length - 2)
                {
                    return false;
                }

                int pointer = ((marker & 0x3F) << 8) | packet[offset + 1];
                if (pointer >= packet.Length || !visitedPointers.Add(pointer) || ++jumpCount > 16)
                {
                    return false;
                }

                if (!jumped)
                {
                    nextOffset = offset + 2;
                    jumped = true;
                }

                offset = pointer;
                continue;
            }

            if ((marker & 0xC0) != 0)
            {
                return false;
            }

            offset++;
            if (marker == 0)
            {
                if (!jumped)
                {
                    nextOffset = offset;
                }

                if (labels.Count == 0)
                {
                    return false;
                }

                name = string.Join('.', labels).ToLowerInvariant();
                return true;
            }

            int labelLength = marker;
            if (labelLength > 63 || offset > packet.Length - labelLength)
            {
                return false;
            }

            ReadOnlySpan<byte> labelBytes = packet.Slice(offset, labelLength);
            if (!IsValidLabelBytes(labelBytes))
            {
                return false;
            }

            expandedLength += labelLength + (labels.Count == 0 ? 0 : 1);
            if (expandedLength > 253)
            {
                return false;
            }

            labels.Add(Encoding.ASCII.GetString(labelBytes));
            offset += labelLength;
        }
    }

    private static bool IsValidLabelBytes(ReadOnlySpan<byte> label)
    {
        foreach (byte value in label)
        {
            if (value is <= 0x20 or > 0x7E || value == (byte)'.')
            {
                return false;
            }
        }

        return true;
    }
}
