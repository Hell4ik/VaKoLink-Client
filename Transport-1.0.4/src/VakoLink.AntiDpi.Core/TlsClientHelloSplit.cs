using System.Buffers.Binary;
using System.Text;

namespace VakoLink.AntiDpi.Core;

public static class TlsClientHelloSplit
{
    public const int MaximumOriginalLength = 16_384;
    public const int MaximumSplitsPerConnection = 2; // Retransmission allowance; never an unbounded loop.
    public static bool IsDiscordHost(string host) => new[] { "discord.com", "discordapp.com", "discord.gg", "discord.media", "discordapp.net" }
        .Any(root => host.Equals(root, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + root, StringComparison.OrdinalIgnoreCase));

    // Parses a bounded plaintext ClientHello prefix with a COMPLETE SNI extension. The rest
    // of a large/PQ ClientHello may arrive in later TCP segments and is passed unchanged.
    // No full SNI/payload survives the call. No complete visible allowed SNI => unchanged.
    // ECH is not decrypted; a complete allowed outer SNI can still match.
    public static bool TryFindSplit(ReadOnlySpan<byte> payload, out int split, out string reason, bool diagnosticAnyHost = false)
        => TryFindSplit(payload, out split, out reason, out _, diagnosticAnyHost);

    public static bool TryFindSplit(ReadOnlySpan<byte> payload, out int split, out string reason, out TlsSniEvidence? sni, bool diagnosticAnyHost = false)
    {
        sni = null;
        split = 0; reason = "NOT_COMPLETE_CLIENT_HELLO";
        if (payload.Length < 9 || payload[0] != 22 || payload[1] != 3 || payload[5] != 1) return false;
        int record = BinaryPrimitives.ReadUInt16BigEndian(payload[3..]);
        int handshake = (payload[6] << 16) | (payload[7] << 8) | payload[8];
        if (record > MaximumOriginalLength || handshake + 4 > record || handshake < 38) return false;
        var end = 9 + handshake;
        var available = Math.Min(end, payload.Length);
        int at = 43; // record + handshake + legacy_version + random
        if (at >= available) return false;
        var session = payload[at++]; at += session;
        if (at + 2 > available) return false;
        var ciphers = BinaryPrimitives.ReadUInt16BigEndian(payload[at..]); at += 2 + ciphers;
        if (ciphers < 2 || (ciphers & 1) != 0 || at >= available) return false;
        var compression = payload[at++]; at += compression;
        if (compression == 0 || at + 2 > available) return false;
        var extensions = BinaryPrimitives.ReadUInt16BigEndian(payload[at..]); at += 2;
        if (at + extensions != end) return false;
        while (at + 4 <= available)
        {
            var type = BinaryPrimitives.ReadUInt16BigEndian(payload[at..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(payload[(at + 2)..]); at += 4;
            if (at + length > end || at + length > available) return false;
            if (type == 0)
            {
                if (length < 6 || BinaryPrimitives.ReadUInt16BigEndian(payload[at..]) != length - 2 || payload[at + 2] != 0) return false;
                var hostLength = BinaryPrimitives.ReadUInt16BigEndian(payload[(at + 3)..]);
                if (hostLength is < 2 or > 253 || hostLength + 5 != length) return false;
                var name = payload.Slice(at + 5, hostLength);
                foreach (var b in name) if (!(b is >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z'
                    or >= (byte)'0' and <= (byte)'9' or (byte)'.' or (byte)'-')) return false;
                sni = TlsSniEvidence.FromHost(Encoding.ASCII.GetString(name));
                if (!diagnosticAnyHost && !IsDiscordHost(Encoding.ASCII.GetString(name))) { reason = "SNI_NOT_DISCORD"; return false; }
                split = at + 5 + Math.Max(1, hostLength / 2); reason = "DISCORD_CLIENT_HELLO_SNI_SPLIT"; return true;
            }
            at += length;
        }
        reason = "SNI_ABSENT_OR_ENCRYPTED"; return false;
    }

    public static byte[][] Build(byte[] original, int split)
    {
        if (!TcpPacket.TryParse(original, out var tcp) || tcp is null || original.Length > MaximumOriginalLength
            || tcp.PayloadLength < 2 || split <= 0 || split >= tcp.PayloadLength
            || tcp.Flags is not (0x10 or 0x18)) // ACK, optional PSH only; no control/ECN flags.
            throw new ArgumentException("TCP_SPLIT_CONTRACT");
        return [Segment(original, tcp, 0, split, false), Segment(original, tcp, split, tcp.PayloadLength - split, true)];
    }
    // Same stream, split after record byte 1 and inside visible SNI, sent tail -> middle -> head.
    // No fake/overlap/timestamp/ACK mutation. The peer must reassemble ordinary TCP sequence ranges.
    public static byte[][] BuildDisorder(byte[] original, int split)
    {
        if (!TcpPacket.TryParse(original, out var tcp) || tcp is null || original.Length > MaximumOriginalLength
            || split <= 1 || split >= tcp.PayloadLength || tcp.Flags is not (0x10 or 0x18))
            throw new ArgumentException("TCP_DISORDER_CONTRACT");
        var head = Segment(original, tcp, 0, 1, false);
        var middle = Segment(original, tcp, 1, split - 1, false);
        var tail = Segment(original, tcp, split, tcp.PayloadLength - split, true);
        if (!tcp.IsV6)
        {
            var id = BinaryPrimitives.ReadUInt16BigEndian(original.AsSpan(4));
            foreach (var pair in new[] { (head, 0), (middle, 1), (tail, 2) })
            {
                BinaryPrimitives.WriteUInt16BigEndian(pair.Item1.AsSpan(4), unchecked((ushort)(id + pair.Item2)));
                pair.Item1[10] = pair.Item1[11] = 0;
                BinaryPrimitives.WriteUInt16BigEndian(pair.Item1.AsSpan(10), InternetChecksum.Compute(pair.Item1.AsSpan(0, tcp.IpLength)));
            }
        }
        return [tail, middle, head];
    }
    internal static byte[] Segment(byte[] original, TcpPacket tcp, int offset, int count, bool last)
    {
        var result = new byte[tcp.PayloadOffset + count]; original.AsSpan(0, tcp.PayloadOffset).CopyTo(result);
        original.AsSpan(tcp.PayloadOffset + offset, count).CopyTo(result.AsSpan(tcp.PayloadOffset));
        if (tcp.IsV6) BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), (ushort)(result.Length - 40));
        else
        {
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2), (ushort)result.Length);
            result[10] = result[11] = 0;
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(10), InternetChecksum.Compute(result.AsSpan(0, tcp.IpLength)));
        }
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(tcp.IpLength + 4), unchecked(tcp.Sequence + (uint)offset));
        if (!last) result[tcp.IpLength + 13] &= 0xF7; // PSH belongs to final segment.
        result[tcp.IpLength + 16] = result[tcp.IpLength + 17] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(tcp.IpLength + 16), Checksum(result, tcp));
        return result;
    }
    public static ushort Checksum(ReadOnlySpan<byte> packet, TcpPacket tcp)
    {
        int length = packet.Length - tcp.IpLength;
        var pseudo = new byte[(tcp.IsV6 ? 40 : 12) + length];
        if (tcp.IsV6)
        {
            packet.Slice(8, 32).CopyTo(pseudo);
            BinaryPrimitives.WriteUInt32BigEndian(pseudo.AsSpan(32), (uint)length); pseudo[39] = 6;
            packet[tcp.IpLength..].CopyTo(pseudo.AsSpan(40));
        }
        else
        {
            packet.Slice(12, 8).CopyTo(pseudo); pseudo[9] = 6;
            BinaryPrimitives.WriteUInt16BigEndian(pseudo.AsSpan(10), (ushort)length);
            packet[tcp.IpLength..].CopyTo(pseudo.AsSpan(12));
        }
        return InternetChecksum.Compute(pseudo);
    }
}
