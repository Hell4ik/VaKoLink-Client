using System.Buffers.Binary;
using System.Security.Cryptography;

namespace VakoLink.AntiDpi.Core;

public sealed record TcpHandshakeProgress(int DeclaredRecordBytes, int ObservedContiguousBytes,
    long OriginalRangeCopies, long ExactRangeRetransmissions, long ChangedRangeCopies, long ResegmentedCopies,
    long PeerAckCopies, int MaximumAcknowledgedBytes, long AckOutsideTrackingBound, bool RecordAcknowledged);

// Diagnostic only. Never supplies capture authorization, packet bytes, a split or a changed deadline.
public sealed class TcpHandshakeTracker : IDisposable
{
    private readonly Dictionary<(int Offset, int Length), byte[]> _ranges = new();
    private uint? _anchor;
    private int _declared, _contiguous, _acked;
    private long _copies, _exact, _changed, _resegmented, _acks, _outside;
    private bool _disposed;
    public (string Relation, int? RelativeSequence) ObserveOriginal(uint sequence, ReadOnlySpan<byte> payload)
    {
        if (_disposed) return ("TRACKER_STOPPED", null);
        if (_anchor is null && payload.Length >= 9 && payload[0] == 22 && payload[1] == 3 && payload[5] == 1)
        {
            var declared = 5 + BinaryPrimitives.ReadUInt16BigEndian(payload[3..]);
            if (declared is >= 9 and <= TlsClientHelloSplit.MaximumOriginalLength) { _anchor = sequence; _declared = declared; }
        }
        if (_anchor is null) return ("NOT_TRACKED_CLIENT_HELLO", null);
        var offset = unchecked((int)(sequence - _anchor.Value));
        if (offset < 0 || offset >= _declared || payload.Length == 0 || payload.Length > TlsClientHelloSplit.MaximumOriginalLength)
            return ("OUTSIDE_CLIENT_HELLO", null);
        _copies++;
        var key = (offset, payload.Length); var hash = SHA256.HashData(payload);
        string relation;
        if (_ranges.TryGetValue(key, out var previous))
        {
            bool identical = CryptographicOperations.FixedTimeEquals(previous, hash);
            if (identical) { _exact++; relation = "IDENTICAL_RANGE_RETRANSMISSION"; }
            else { _changed++; relation = "SAME_RANGE_CHANGED_BYTES"; }
            CryptographicOperations.ZeroMemory(hash);
        }
        else if (_ranges.Count >= 16) { CryptographicOperations.ZeroMemory(hash); relation = "RANGE_TRACKING_LIMIT"; }
        else
        {
            var length = payload.Length;
            var resegmented = _ranges.Keys.Any(range => range.Offset < offset + length && offset < range.Offset + range.Length);
            if (resegmented) _resegmented++;
            relation = resegmented ? "OVERLAPPING_NEW_RANGE" : "NEW_CONTIGUOUS_RANGE";
            _ranges.Add(key, hash);
            int end = 0;
            foreach (var range in _ranges.Keys.OrderBy(range => range.Offset))
                if (range.Offset <= end) end = Math.Max(end, range.Offset + range.Length);
            _contiguous = Math.Min(end, _declared);
        }
        return (relation, offset);
    }
    public void ObservePeerAck(uint acknowledgment)
    {
        if (_disposed || _anchor is null) return;
        _acks++;
        var delta = unchecked(acknowledgment - _anchor.Value);
        // Fake+0x80000000 cannot count as progress. Allow bounded real bytes after the record, clamp export.
        if (delta > (uint)(_declared + TlsClientHelloSplit.MaximumOriginalLength)) { _outside++; return; }
        _acked = Math.Max(_acked, Math.Min((int)delta, _declared));
    }
    public TcpHandshakeProgress Snapshot() => new(_declared, _contiguous, _copies, _exact, _changed, _resegmented,
        _acks, _acked, _outside, _declared > 0 && _acked == _declared);
    public void Dispose()
    {
        foreach (var hash in _ranges.Values) CryptographicOperations.ZeroMemory(hash);
        _ranges.Clear(); _disposed = true;
    }
}
