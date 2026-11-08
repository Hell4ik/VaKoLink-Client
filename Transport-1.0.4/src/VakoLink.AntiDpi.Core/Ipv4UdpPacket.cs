using System.Buffers.Binary;

namespace VakoLink.AntiDpi.Core;

/// <summary>Addresses are unsigned integers in network (big-endian) byte order.</summary>
public readonly record struct FlowKey(uint SourceAddress, ushort SourcePort, uint DestinationAddress, ushort DestinationPort);

public sealed record UdpPacketInfo(FlowKey Flow, int HeaderLength, int PayloadOffset, int TotalLength);

public static class Ipv4UdpPacket
{
    /// <summary>
    /// Parses one complete, unfragmented IPv4 UDP datagram. Trailing receive-buffer bytes are ignored.
    /// This validates structure only; process ownership and permitted destinations are caller responsibilities.
    /// </summary>
    public static bool TryParse(ReadOnlySpan<byte> packet, out UdpPacketInfo? info)
    {
        info = null;
        if (packet.Length < 28 || (packet[0] >> 4) != 4 || packet[9] != 17)
        {
            return false;
        }

        var headerLength = (packet[0] & 0x0F) * 4;
        var totalLength = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(2, 2));
        var fragment = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(6, 2));
        if (headerLength < 20 || headerLength > packet.Length
            || totalLength < headerLength + 8 || totalLength > packet.Length
            || (fragment & 0xBFFF) != 0)
        {
            // Reserved flag, More Fragments, or a nonzero fragment offset are never processed.
            return false;
        }

        var udpLength = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(headerLength + 4, 2));
        if (udpLength < 8 || udpLength != totalLength - headerLength)
        {
            return false;
        }

        var flow = new FlowKey(
            BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(12, 4)),
            BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(headerLength, 2)),
            BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(16, 4)),
            BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(headerLength + 2, 2)));
        if (flow.SourcePort == 0 || flow.DestinationPort == 0)
        {
            return false;
        }

        info = new UdpPacketInfo(flow, headerLength, headerLength + 8, totalLength);
        return true;
    }
}

public static class InternetChecksum
{
    public static ushort Compute(ReadOnlySpan<byte> bytes)
    {
        uint sum = 0;
        for (var index = 0; index + 1 < bytes.Length; index += 2)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(index, 2));
        }

        if ((bytes.Length & 1) != 0)
        {
            sum += (uint)bytes[^1] << 8;
        }

        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return (ushort)~sum;
    }

    public static ushort ComputeUdp(ReadOnlySpan<byte> ipv4Packet)
    {
        if (!Ipv4UdpPacket.TryParse(ipv4Packet, out var info) || info is null)
        {
            throw new ArgumentException("A complete IPv4 UDP packet is required.", nameof(ipv4Packet));
        }

        var udpLength = info.TotalLength - info.HeaderLength;
        Span<byte> pseudoHeader = stackalloc byte[12];
        ipv4Packet.Slice(12, 8).CopyTo(pseudoHeader);
        pseudoHeader[8] = 0;
        pseudoHeader[9] = 17;
        BinaryPrimitives.WriteUInt16BigEndian(pseudoHeader.Slice(10, 2), (ushort)udpLength);
        // UDP is bounded by the IPv4 length. A 65,535-byte allocation is the worst case.
        var checksumData = new byte[12 + udpLength];
        pseudoHeader.CopyTo(checksumData);
        ipv4Packet.Slice(info.HeaderLength, udpLength).CopyTo(checksumData.AsSpan(12));
        return Compute(checksumData);
    }
}
