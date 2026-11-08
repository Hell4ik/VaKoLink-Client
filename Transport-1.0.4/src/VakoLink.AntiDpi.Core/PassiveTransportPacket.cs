using System.Buffers.Binary;

namespace VakoLink.AntiDpi.Core;

// Metadata only. Does not expose payload, mutate packets or grant ownership.
public sealed record PassiveTransportPacket(TcpFlow Flow, byte Protocol, int PayloadBytes)
{
    public static bool TryParse(ReadOnlySpan<byte> bytes, out PassiveTransportPacket? packet)
    {
        packet = null;
        if (bytes.Length < 20) return false;
        int offset, total; byte protocol; PacketAddress source, destination;
        if (bytes[0] >> 4 == 4)
        {
            offset = (bytes[0] & 15) * 4; total = BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]); protocol = bytes[9];
            if (offset < 20 || (BinaryPrimitives.ReadUInt16BigEndian(bytes[6..]) & 0xBFFF) != 0) return false;
            source = PacketAddress.Read(bytes[12..], false); destination = PacketAddress.Read(bytes[16..], false);
        }
        else if (bytes[0] >> 4 == 6 && bytes.Length >= 40)
        {
            offset = 40; total = 40 + BinaryPrimitives.ReadUInt16BigEndian(bytes[4..]); protocol = bytes[6];
            source = PacketAddress.Read(bytes[8..], true); destination = PacketAddress.Read(bytes[24..], true);
            for (int count = 0; protocol is 0 or 43 or 60 or 51; count++)
            {
                if (count >= 8 || offset + 2 > bytes.Length) return false;
                int length = protocol == 51 ? (bytes[offset + 1] + 2) * 4 : (bytes[offset + 1] + 1) * 8;
                protocol = bytes[offset]; offset += length;
                if (offset > bytes.Length) return false;
            }
            // Fragments/ESP/jumbograms cannot be safely attributed by this metadata parser.
        }
        else return false;
        if (total != bytes.Length || offset > total - 8 || protocol is not (6 or 17)) return false;
        int header;
        if (protocol == 6)
        {
            if (offset > total - 20) return false;
            header = (bytes[offset + 12] >> 4) * 4;
            if (header < 20 || header > total - offset) return false;
        }
        else { header = 8; if (BinaryPrimitives.ReadUInt16BigEndian(bytes[(offset + 4)..]) != total - offset) return false; }
        var local = BinaryPrimitives.ReadUInt16BigEndian(bytes[offset..]); var remote = BinaryPrimitives.ReadUInt16BigEndian(bytes[(offset + 2)..]);
        if (local == 0 || remote == 0) return false;
        packet = new(new(source, local, destination, remote), protocol, total - offset - header); return true;
    }
}
