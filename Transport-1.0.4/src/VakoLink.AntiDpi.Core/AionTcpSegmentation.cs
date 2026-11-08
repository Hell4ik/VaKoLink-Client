using System.Buffers.Binary;

namespace VakoLink.AntiDpi.Core;

public static class AionTcpSegmentation
{
    public const int PayloadLimit = 1000;
    public const int MaximumOriginalIpBytes = 16384;
    public const int MaximumPerFlow = 4096;
    public const int MaximumPerSession = 8192;
    public const int MaximumFlows = 16;
    public const ushort TargetPort = 13328;
    public const string TargetAddressSha256 = "4CC49135DE53AAD2105EC3C54DC0391823CBAF784F6EB0D640575C1F74F645B0";
    public const string ClientImageSha256 = "3842FC511A09121D3B3F2567002994D5C2CFDBA0CF762D035C8AE21872ABA953";
    public const string StrategyId = "aion-tcp13328-payload1000-ordered";
    public static bool TryBuild(byte[] original, out byte[][] segments, out string reason)
    {
        segments = []; reason = "SEGMENT_CONTRACT_REFUSED";
        if (!TcpPacket.TryParse(original, out var tcp) || tcp is null || tcp.IsV6 || tcp.IpLength != 20
            || original.Length > MaximumOriginalIpBytes || tcp.PayloadLength <= PayloadLimit || tcp.Flags is not (16 or 24)) return false;
        var options = original.AsSpan(tcp.IpLength + 20, tcp.TcpLength - 20);
        for (int at = 0; at < options.Length;)
        {
            byte kind = options[at]; if (kind == 0) break; if (kind == 1) { at++; continue; }
            if (at + 2 > options.Length || options[at + 1] < 2 || at + options[at + 1] > options.Length) return false;
            if (kind is 19 or 29) { reason = "TCP_AUTH_OPTION_UNCHANGED"; return false; }
            at += options[at + 1];
        }
        var result = new List<byte[]>();
        for (int offset = 0; offset < tcp.PayloadLength; offset += PayloadLimit)
        {
            int count = Math.Min(PayloadLimit, tcp.PayloadLength - offset);
            var segment = TlsClientHelloSplit.Segment(original, tcp, offset, count, offset + count == tcp.PayloadLength);
            BinaryPrimitives.WriteUInt16BigEndian(segment.AsSpan(4), unchecked((ushort)(BinaryPrimitives.ReadUInt16BigEndian(original.AsSpan(4)) + result.Count)));
            segment[10] = segment[11] = 0;
            BinaryPrimitives.WriteUInt16BigEndian(segment.AsSpan(10), InternetChecksum.Compute(segment.AsSpan(0, 20)));
            result.Add(segment);
        }
        segments = result.ToArray();
        if (!PreservesStream(original, segments)) { segments = []; reason = "SEGMENT_STREAM_CHECK_FAILED"; return false; }
        reason = "ORDERED_PAYLOAD_1000"; return true;
    }
    public static bool PreservesStream(byte[] original, IReadOnlyList<byte[]> segments)
    {
        if (!TcpPacket.TryParse(original, out var p) || p is null || segments.Count is < 2 or > 17) return false;
        int offset = 0;
        foreach (var bytes in segments)
        {
            if (!TcpPacket.TryParse(bytes, out var s) || s is null || s.Flow != p.Flow || s.PayloadLength is < 1 or > PayloadLimit
                || offset + s.PayloadLength > p.PayloadLength
                || s.Sequence != unchecked(p.Sequence + (uint)offset) || s.Acknowledgment != p.Acknowledgment
                || s.Flags != (offset + s.PayloadLength == p.PayloadLength ? p.Flags : (byte)(p.Flags & ~8))
                || InternetChecksum.Compute(bytes.AsSpan(0, s.IpLength)) != 0 || TlsClientHelloSplit.Checksum(bytes, s) != 0
                || !original.AsSpan(p.PayloadOffset + offset, s.PayloadLength).SequenceEqual(bytes.AsSpan(s.PayloadOffset))) return false;
            offset += s.PayloadLength;
        }
        return offset == p.PayloadLength;
    }
}
