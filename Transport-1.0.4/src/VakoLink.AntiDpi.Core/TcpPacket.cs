using System.Buffers.Binary;

namespace VakoLink.AntiDpi.Core;

// Addresses deliberately have no string formatter; never export a tuple in a report.
public readonly record struct PacketAddress(uint A, uint B, uint C, uint D, bool V6)
{
    public static PacketAddress Read(ReadOnlySpan<byte> bytes, bool v6) => v6
        ? new(BinaryPrimitives.ReadUInt32BigEndian(bytes), BinaryPrimitives.ReadUInt32BigEndian(bytes[4..]),
            BinaryPrimitives.ReadUInt32BigEndian(bytes[8..]), BinaryPrimitives.ReadUInt32BigEndian(bytes[12..]), true)
        : new(BinaryPrimitives.ReadUInt32BigEndian(bytes), 0, 0, 0, false);
}
public readonly record struct TcpFlow(PacketAddress Local, ushort LocalPort, PacketAddress Remote, ushort RemotePort)
{
    public TcpFlow Reverse() => new(Remote, RemotePort, Local, LocalPort);
}
public sealed record TcpPacket(TcpFlow Flow, int IpLength, int TcpLength, int TotalLength, byte Flags, uint Sequence, uint Acknowledgment = 0)
{
    public int PayloadOffset => IpLength + TcpLength;
    public int PayloadLength => TotalLength - PayloadOffset;
    public bool IsV6 => Flow.Local.V6;
    public static bool TryParse(ReadOnlySpan<byte> bytes, out TcpPacket? packet)
    {
        packet = null;
        if (bytes.Length < 40) return false;
        var v6 = bytes[0] >> 4 == 6;
        int ip, total;
        PacketAddress local, remote;
        if (v6)
        {
            // Extension headers, fragments and jumbograms are passed unchanged, not guessed.
            if (bytes[6] != 6 || bytes.Length < 60) return false;
            ip = 40; total = 40 + BinaryPrimitives.ReadUInt16BigEndian(bytes[4..]);
            local = PacketAddress.Read(bytes[8..], true); remote = PacketAddress.Read(bytes[24..], true);
        }
        else
        {
            if (bytes[0] >> 4 != 4 || bytes[9] != 6 || (BinaryPrimitives.ReadUInt16BigEndian(bytes[6..]) & 0xBFFF) != 0) return false;
            ip = (bytes[0] & 15) * 4; total = BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]);
            local = PacketAddress.Read(bytes[12..], false); remote = PacketAddress.Read(bytes[16..], false);
        }
        if (ip < 20 || total != bytes.Length || total < ip + 20) return false;
        var tcp = (bytes[ip + 12] >> 4) * 4;
        if (tcp < 20 || ip + tcp > total || (bytes[ip + 12] & 15) != 0) return false;
        var lp = BinaryPrimitives.ReadUInt16BigEndian(bytes[ip..]); var rp = BinaryPrimitives.ReadUInt16BigEndian(bytes[(ip + 2)..]);
        if (lp == 0 || rp == 0) return false;
        packet = new(new(local, lp, remote, rp), ip, tcp, total, bytes[ip + 13], BinaryPrimitives.ReadUInt32BigEndian(bytes[(ip + 4)..]), BinaryPrimitives.ReadUInt32BigEndian(bytes[(ip + 8)..]));
        return true;
    }
}
