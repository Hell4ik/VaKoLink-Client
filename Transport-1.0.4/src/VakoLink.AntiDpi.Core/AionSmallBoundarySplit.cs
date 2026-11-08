using System.Buffers.Binary;

namespace VakoLink.AntiDpi.Core;

// Packet-boundary experiment for the actual first failed small ranges, NOT an MTU policy.
public static class AionSmallBoundarySplit
{
    public const string StrategyId = "aion-tcp13328-small11-boundary1-10";
    public const int OriginalPayload = 11, MaximumSentPayload = 10;
    public static bool TryBuild(byte[] original, out byte[][] pieces, out string reason)
    {
        pieces = []; reason = "SMALL11_CONTRACT_UNCHANGED";
        if (!TcpPacket.TryParse(original, out var p) || p is null || p.IsV6 || p.IpLength != 20 || p.PayloadLength != OriginalPayload || p.Flags is not (16 or 24)) return false;
        var options = original.AsSpan(p.IpLength + 20, p.TcpLength - 20);
        for (int at = 0; at < options.Length;)
        {
            byte kind = options[at]; if (kind == 0) break; if (kind == 1) { at++; continue; }
            if (at + 2 > options.Length || options[at + 1] < 2 || at + options[at + 1] > options.Length) return false;
            if (kind is 19 or 29) { reason = "TCP_AUTH_OPTION_UNCHANGED"; return false; }
            at += options[at + 1];
        }
        pieces = [TlsClientHelloSplit.Segment(original, p, 0, 1, false), TlsClientHelloSplit.Segment(original, p, 1, 10, true)];
        BinaryPrimitives.WriteUInt16BigEndian(pieces[1].AsSpan(4), unchecked((ushort)(BinaryPrimitives.ReadUInt16BigEndian(original.AsSpan(4)) + 1)));
        pieces[1][10] = pieces[1][11] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(pieces[1].AsSpan(10), InternetChecksum.Compute(pieces[1].AsSpan(0, 20)));
        if (!AionTcpSegmentation.PreservesStream(original, pieces)) { pieces = []; reason = "SMALL11_STREAM_CHECK_FAILED"; return false; }
        reason = "ORDERED_SMALL11_BOUNDARY_REPLACED"; return true;
    }
}
