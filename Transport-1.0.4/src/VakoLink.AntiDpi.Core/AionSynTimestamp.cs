using System.Buffers.Binary;

namespace VakoLink.AntiDpi.Core;

// Negotiation experiment, NOT stripping an option from an already-negotiated data stream.
public static class AionSynTimestamp
{
    public const string StrategyId = "aion-syn-timestamp-off";
    public const int MaximumFlows = 16, MaximumSynPerFlow = 8, MaximumSynPerSession = 128, ProofWaitMilliseconds = 100;
    public static bool? TimestampPresent(ReadOnlySpan<byte> bytes)
    {
        if (!TcpPacket.TryParse(bytes, out var p) || p is null) return null;
        bool found = false;
        for (int at = p.IpLength + 20; at < p.PayloadOffset;)
        {
            byte kind = bytes[at]; if (kind == 0) break; if (kind == 1) { at++; continue; }
            if (at + 2 > p.PayloadOffset || bytes[at + 1] < 2 || at + bytes[at + 1] > p.PayloadOffset) return null;
            if (kind == 8) { if (bytes[at + 1] != 10 || found) return null; found = true; }
            at += bytes[at + 1];
        }
        return found;
    }
    public static bool TryBuild(ReadOnlySpan<byte> original, out byte[] changed, out string reason)
    {
        changed = []; reason = "NOT_PLAIN_IPV4_SYN";
        if (!TcpPacket.TryParse(original, out var p) || p is null || p.IsV6 || p.IpLength != 20 || p.Flags != 2 || p.PayloadLength != 0) return false;
        int timestamp = -1;
        for (int at = 40; at < p.PayloadOffset;)
        {
            byte kind = original[at]; if (kind == 0) break; if (kind == 1) { at++; continue; }
            reason = "SYN_OPTIONS_INVALID";
            if (at + 2 > p.PayloadOffset || original[at + 1] < 2 || at + original[at + 1] > p.PayloadOffset) return false;
            if (kind is 19 or 29 or 34) { reason = "AUTH_OR_FASTOPEN_UNCHANGED"; return false; }
            if (kind == 8) { if (original[at + 1] != 10 || timestamp >= 0) return false; timestamp = at; }
            at += original[at + 1];
        }
        if (timestamp < 0) { reason = "SYN_ALREADY_WITHOUT_TIMESTAMP"; return false; }
        changed = original.ToArray(); changed.AsSpan(timestamp, 10).Fill(1); // ten valid NOPs: preserve offsets, MSS/WS/SACK and SYN length.
        changed[10] = changed[11] = changed[36] = changed[37] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(changed.AsSpan(10), InternetChecksum.Compute(changed.AsSpan(0, 20)));
        BinaryPrimitives.WriteUInt16BigEndian(changed.AsSpan(36), TlsClientHelloSplit.Checksum(changed, p));
        reason = "SYN_TIMESTAMP_OFFER_REMOVED";
        return TimestampPresent(changed) == false && InternetChecksum.Compute(changed.AsSpan(0, 20)) == 0 && TlsClientHelloSplit.Checksum(changed, p) == 0;
    }
    public static bool MatchesCapture(ReadOnlySpan<byte> original, ReadOnlySpan<byte> after)
    {
        if (!TryBuild(original, out var expected, out _) || expected.Length != after.Length) return false;
        // Capture checksum fields can be pending offload. Generated checksums are independently validated above.
        for (int i = 0; i < expected.Length; i++) if (i is not (10 or 11 or 36 or 37) && expected[i] != after[i]) return false;
        return true;
    }
}
