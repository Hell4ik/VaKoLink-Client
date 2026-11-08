using System.Buffers.Binary;

namespace VakoLink.AntiDpi.Core;

public static class TcpTimestampOptions
{
    // Data packet TS + nonzero echoed peer TS is the bounded stack-level eligibility evidence.
    // Never enables Windows timestamps or adds an unnegotiated option.
    public static bool TryRead(ReadOnlySpan<byte> packet, TcpPacket tcp, out int offset, out uint value, out uint echo)
    {
        offset = 0; value = echo = 0; bool found = false;
        for (int at = tcp.IpLength + 20; at < tcp.PayloadOffset;)
        {
            byte kind = packet[at]; if (kind == 0) break; if (kind == 1) { at++; continue; }
            if (at + 2 > tcp.PayloadOffset) return false;
            int length = packet[at + 1]; if (length < 2 || at + length > tcp.PayloadOffset) return false;
            if (kind == 8)
            {
                if (length != 10 || found) return false;
                found = true; offset = at + 2;
                value = BinaryPrimitives.ReadUInt32BigEndian(packet[offset..]); echo = BinaryPrimitives.ReadUInt32BigEndian(packet[(offset + 4)..]);
            }
            at += length;
        }
        return found;
    }
}
