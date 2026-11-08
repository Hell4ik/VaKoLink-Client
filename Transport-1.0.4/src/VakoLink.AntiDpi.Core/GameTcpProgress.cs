using System.Security.Cryptography;

namespace VakoLink.AntiDpi.Core;

public sealed record GameTcpCloseSignal(DateTimeOffset Utc, bool Outbound, byte Flags);
public sealed record GameTcpProgress(long PayloadCopies, long ExactRangeRepeatCopies, long ChangedExactRangeCopies,
    long OverlappingRangeCopies, int HighestObservedPayloadEnd, int ContiguousObservedPayloadBytes,
    long PeerAckCopies, long DuplicateAckCopies, int MaximumAcknowledgedOffset, int UnacknowledgedContiguousBytes,
    long OutsideTrackingBound, bool TrackingLimited, DateTimeOffset? LastAckProgressUtc,
    IReadOnlyList<GameTcpCloseSignal> CloseSignals,
    string Limitation = "Observed TCP ranges only, not application semantics; repeats may be retransmission or multi-interface copies; ACK beyond observed prefix does not prove application acceptance",
    long RangeHistoryEvictions = 0, int RetainedRanges = 0, int HighestAcknowledgedObservedPayloadEnd = 0,
    string OriginBasis = "FirstOutboundPayloadIncludingInjected", long SyntheticPayloadCopies = 0, long SyntheticPayloadBytes = 0,
    long PreOriginPayloadCopies = 0, long OriginUnknownCopies = 0);

// Read-only transport metadata for arbitrary TCP, not a TLS-only tracker. No payload/hash exported.
public sealed class GameTcpTracker : IDisposable
{
    public const int MaximumOffset = 8 * 1024 * 1024;
    public const int MaximumRanges = 256;
    private readonly Dictionary<(int Offset, int Length), byte[]> _ranges = new();
    private readonly Queue<(int Offset, int Length)> _rangeOrder = new();
    private readonly List<GameTcpCloseSignal> _close = [];
    private uint? _origin, _lastAck;
    private int _high, _contiguous, _acked;
    private long _copies, _repeat, _changed, _overlap, _acks, _duplicateAck, _outside, _evictions;
    private bool _limited, _disposed;
    private DateTimeOffset? _lastProgress;
    private readonly bool _requireSyn;
    private string _basis;
    private long _synthetic, _syntheticBytes, _preOrigin, _unknownOrigin;
    public GameTcpTracker(bool requireSyn = false) { _requireSyn = requireSyn; _basis = requireSyn ? "Unknown" : "FirstOutboundPayloadIncludingInjected"; }
    public void Observe(uint sequence, uint acknowledgment, byte flags, ReadOnlySpan<byte> payload, bool outbound, DateTimeOffset utc, bool synthetic = false)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(GameTcpTracker));
        if (_requireSyn && _origin is null && (flags & 2) != 0)
        {
            if (outbound) { _origin = unchecked(sequence + 1); _basis = "LocalSyn"; }
            else if ((flags & 16) != 0) { _origin = acknowledgment; _basis = "PeerSynAck"; }
        }
        if ((flags & 5) != 0 && _close.Count < 8) _close.Add(new(utc, outbound, (byte)(flags & 5)));
        if (outbound && payload.Length > 0)
        {
            if (synthetic) { _synthetic++; _syntheticBytes += payload.Length; return; }
            if (_requireSyn && _origin is null) { _unknownOrigin++; return; }
            _origin ??= sequence;
            int offset = unchecked((int)(sequence - _origin.Value));
            if (_requireSyn && offset < 0) { _preOrigin++; return; } // Not a lost packet or real stream byte.
            _copies++;
            if (offset < 0 || offset > MaximumOffset - payload.Length) { _outside++; return; }
            var key = (offset, payload.Length); var hash = SHA256.HashData(payload);
            if (_ranges.TryGetValue(key, out var previous))
            {
                if (CryptographicOperations.FixedTimeEquals(previous, hash)) _repeat++; else _changed++;
                CryptographicOperations.ZeroMemory(hash);
            }
            else
            {
                var length = payload.Length;
                if (_ranges.Keys.Any(r => r.Offset < offset + length && offset < r.Offset + r.Length)) _overlap++;
                if (_ranges.Count >= MaximumRanges)
                {
                    var evicted = _rangeOrder.Dequeue(); CryptographicOperations.ZeroMemory(_ranges[evicted]); _ranges.Remove(evicted);
                    _limited = true; _evictions++;
                }
                _rangeOrder.Enqueue(key);
                _ranges.Add(key, hash); _high = Math.Max(_high, offset + payload.Length);
                int end = _contiguous;
                foreach (var range in _ranges.Keys.OrderBy(r => r.Offset)) if (range.Offset <= end) end = Math.Max(end, range.Offset + range.Length);
                _contiguous = end;
            }
        }
        if (!outbound && (flags & 16) != 0 && _origin is not null)
        {
            _acks++;
            if (_lastAck == acknowledgment) _duplicateAck++;
            _lastAck = acknowledgment;
            int offset = unchecked((int)(acknowledgment - _origin.Value));
            if (offset < 0 || offset > MaximumOffset) { _outside++; return; }
            if (offset > _acked) { _acked = offset; _lastProgress = utc; }
        }
    }
    public GameTcpProgress Snapshot() => new(_copies, _repeat, _changed, _overlap, _high, _contiguous, _acks,
        _duplicateAck, _acked, Math.Max(0, _contiguous - _acked), _outside, _limited, _lastProgress, _close.ToArray(),
        "Bounded sliding history of 256 ranges; older repeats may be unrecognised after eviction. ACK may be on a TUN/proxy client-facing leg; not application acceptance", _evictions, _ranges.Count, Math.Min(_acked, _high),
        _basis, _synthetic, _syntheticBytes, _preOrigin, _unknownOrigin);
    public void Dispose()
    { foreach (var hash in _ranges.Values) CryptographicOperations.ZeroMemory(hash); _ranges.Clear(); _rangeOrder.Clear(); _disposed = true; }
}
