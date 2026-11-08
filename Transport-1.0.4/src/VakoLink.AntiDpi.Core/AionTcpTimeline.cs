using System.Buffers.Binary;
using System.Security.Cryptography;

namespace VakoLink.AntiDpi.Core;

public sealed record RelativeTcpRange(int Start, int End);
public sealed record AionTcpMoment(DateTimeOffset Utc, bool Outbound, byte Flags, int PayloadBytes, int? RelativeSequence, int? RelativeAck,
    string RangeRelation, ushort WindowRaw, int? EffectiveWindow, bool OptionsValid, bool TimestampPresent,
    int? TimestampDelta, bool? TimestampMovedBackwards, bool? EchoFoundInRecentOppositeHistory, IReadOnlyList<RelativeTcpRange> SackRanges,
    string OwnershipBasis = "Selected capture", bool Synthetic = false, int SackDiagnosticsVersion = 0,
    int SackBlockCount = 0, int SackBlocksNotExported = 0, string SackOmissionReason = "None");
public sealed record AionIcmpMoment(DateTimeOffset Utc, byte Type, byte Code, int? NextHopMtu, int? QuotedRelativeSequence);
public sealed record AionTcpDetail(bool LocalSynObserved, bool PeerSynObserved, string LocalSynBasis, string LocalOriginBasis, string PeerOriginBasis,
    int? LocalWindowScale, int? PeerWindowScale, bool WindowNegotiationKnown, long TotalEvents, long TimelineDropped,
    long RangeHistoryEvictions, long TimestampHistoryEvictions, long OutsideBound, IReadOnlyList<AionTcpMoment> FirstEvents,
    IReadOnlyList<AionTcpMoment> RecentEvents, IReadOnlyList<AionIcmpMoment> Icmp,
    string Limitation = "Capture metadata, not wire/application acceptance. Correlated SYN is read-only evidence, never process/mutation authorization. Absence of ICMP/SACK does not prove absence on the path.");

// Raw sequence numbers, TS values and internal payload hashes never enter the exported evidence.
public sealed class AionTcpTimeline : IDisposable
{
    public const int FirstLimit = 512, TailLimit = 64, RangeLimit = 256, TimestampLimit = 64, IcmpLimit = 16, FlowLimit = 2;
    private readonly List<AionTcpMoment> _first = [];
    private readonly Queue<AionTcpMoment> _tail = new();
    private readonly List<AionIcmpMoment> _icmp = [];
    private readonly Dictionary<(bool, int, int), byte[]> _ranges = new();
    private readonly Queue<(bool, int, int)> _rangeOrder = new();
    private readonly Queue<uint> _localTs = new(), _peerTs = new();
    private uint? _localOrigin, _peerOrigin, _localTsOrigin, _peerTsOrigin, _lastLocalTs, _lastPeerTs;
    private bool _localSyn, _peerSyn, _localOptionsValid, _peerOptionsValid;
    private int? _localScale, _peerScale;
    private string _synBasis = "NotObserved", _localBasis = "Unknown", _peerBasis = "Unknown";
    private long _total, _evictions, _tsEvictions, _outside;
    private bool _disposed;
    private readonly bool _requireSyn;
    public AionTcpTimeline(bool requireSyn = false) => _requireSyn = requireSyn;
    public static bool MatchingSynCandidate(byte[] header, TcpPacket synAck) => TcpPacket.TryParse(header, out var syn)
        && syn is { Flags: 2, PayloadLength: 0 } && synAck.Flags == 18 && syn.Flow == synAck.Flow.Reverse()
        && unchecked(syn.Sequence + 1) == synAck.Acknowledgment;
    public void Observe(TcpPacket p, ReadOnlySpan<byte> bytes, bool outbound, DateTimeOffset utc, string ownershipBasis = "Selected capture", bool synthetic = false)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(AionTcpTimeline));
        var options = ReadOptions(p, bytes);
        if ((p.Flags & 2) != 0)
        {
            if (outbound)
            { _localSyn = true; _synBasis = ownershipBasis; _localOptionsValid = options.Valid; _localScale = options.Scale; SetOrigin(true, unchecked(p.Sequence + 1), "LocalSyn"); }
            else
            {
                _peerSyn = true; _peerOptionsValid = options.Valid; _peerScale = options.Scale;
                SetOrigin(false, unchecked(p.Sequence + 1), "PeerSyn");
                if ((p.Flags & 16) != 0) SetOrigin(true, p.Acknowledgment, "PeerSynAck");
            }
        }
        if (!_requireSyn && !synthetic && p.PayloadLength > 0) SetOrigin(outbound, p.Sequence, "FirstSelectedPayload");
        int? sequence = Relative(p.Sequence, outbound ? _localOrigin : _peerOrigin, (p.Flags & 2) != 0);
        int? ack = (p.Flags & 16) != 0 ? Relative(p.Acknowledgment, outbound ? _peerOrigin : _localOrigin) : null;
        string relation = "NoPayload";
        if (synthetic) relation = "Synthetic";
        else if (p.PayloadLength > 0)
        {
            if (sequence < 0) relation = "PreOriginNonStream";
            else if (sequence is null || sequence > GameTcpTracker.MaximumOffset - p.PayloadLength) relation = "OutsideBoundOrOriginUnknown";
            else
            {
                var key = (outbound, sequence.Value, p.PayloadLength); var hash = SHA256.HashData(bytes.Slice(p.PayloadOffset, p.PayloadLength));
                if (_ranges.TryGetValue(key, out var previous))
                { relation = CryptographicOperations.FixedTimeEquals(hash, previous) ? "ExactRepeat" : "ChangedExactRepeat"; CryptographicOperations.ZeroMemory(hash); }
                else
                {
                    int start = sequence.Value, length = p.PayloadLength;
                    relation = _ranges.Keys.Any(k => k.Item1 == outbound && k.Item2 < start + length && start < k.Item2 + k.Item3) ? "Overlap" : "New";
                    if (_ranges.Count == RangeLimit) { var old = _rangeOrder.Dequeue(); CryptographicOperations.ZeroMemory(_ranges[old]); _ranges.Remove(old); _evictions++; }
                    _ranges.Add(key, hash); _rangeOrder.Enqueue(key);
                }
            }
        }
        ushort window = BinaryPrimitives.ReadUInt16BigEndian(bytes[(p.IpLength + 14)..]);
        int? effective = (p.Flags & 2) != 0 ? window : NegotiationKnown ? window << EffectiveShift(outbound) : null;
        uint? tsOrigin = outbound ? _localTsOrigin : _peerTsOrigin, previousTs = outbound ? _lastLocalTs : _lastPeerTs;
        int? tsDelta = null; bool? backwards = null, echoFound = null;
        if (options.Timestamp is uint ts)
        {
            tsOrigin ??= ts; tsDelta = unchecked((int)(ts - tsOrigin.Value));
            if (previousTs is uint prior) backwards = unchecked((int)(ts - prior)) < 0;
            var other = outbound ? _peerTs : _localTs;
            if (options.Echo is uint echo && echo != 0 && other.Count > 0) echoFound = other.Contains(echo);
            var history = outbound ? _localTs : _peerTs;
            if (!history.Contains(ts)) { if (history.Count == TimestampLimit) { history.Dequeue(); _tsEvictions++; } history.Enqueue(ts); }
            if (outbound) { _localTsOrigin = tsOrigin; _lastLocalTs = ts; } else { _peerTsOrigin = tsOrigin; _lastPeerTs = ts; }
        }
        var sackOrigin = outbound ? _peerOrigin : _localOrigin;
        var sacks = options.Sacks.Select(b => new { Start = Relative(b.Start, sackOrigin), End = Relative(b.End, sackOrigin) })
            .Where(r => r.Start is not null && r.End > r.Start).Select(r => new RelativeTcpRange(r.Start!.Value, r.End!.Value)).ToArray();
        Add(new(utc, outbound, p.Flags, p.PayloadLength, sequence, ack, relation, window, effective, options.Valid,
            options.Timestamp is not null, tsDelta, backwards, echoFound, sacks, ownershipBasis, synthetic, 1,
            options.Sacks.Count, options.Sacks.Count - sacks.Length,
            options.Sacks.Count == sacks.Length ? "None" : sackOrigin is null ? "OriginUnknown" : "SignedBoundOrInvalidRange"));
    }
    private bool NegotiationKnown => _localSyn && _peerSyn && _localOptionsValid && _peerOptionsValid;
    private int EffectiveShift(bool outbound) => _localScale is not null && _peerScale is not null ? (outbound ? _localScale.Value : _peerScale.Value) : 0;
    private void SetOrigin(bool outbound, uint origin, string basis)
    { if (outbound && _localOrigin is null) { _localOrigin = origin; _localBasis = basis; } else if (!outbound && _peerOrigin is null) { _peerOrigin = origin; _peerBasis = basis; } }
    private int? Relative(uint value, uint? origin, bool syn = false)
    {
        if (origin is null) return null; int offset = unchecked((int)(value - origin.Value));
        if (offset < -GameTcpTracker.MaximumOffset || offset > GameTcpTracker.MaximumOffset) { _outside++; return null; }
        return offset;
    }
    private void Add(AionTcpMoment item)
    { _total++; if (_first.Count < FirstLimit) _first.Add(item); else { if (_tail.Count == TailLimit) _tail.Dequeue(); _tail.Enqueue(item); } }
    public void ObserveIcmp(byte type, byte code, int? mtu, uint quotedSequence, DateTimeOffset utc)
    { if (_icmp.Count < IcmpLimit) _icmp.Add(new(utc, type, code, mtu, Relative(quotedSequence, _localOrigin))); }
    public AionTcpDetail Snapshot() => new(_localSyn, _peerSyn, _synBasis, _localBasis, _peerBasis, _localScale, _peerScale, NegotiationKnown,
        _total, Math.Max(0, _total - _first.Count - _tail.Count), _evictions, _tsEvictions, _outside,
        _first.OrderBy(e => e.Utc).ToArray(), _tail.OrderBy(e => e.Utc).ToArray(), _icmp.ToArray());
    public void Dispose() { foreach (var hash in _ranges.Values) CryptographicOperations.ZeroMemory(hash); _ranges.Clear(); _rangeOrder.Clear(); _localTs.Clear(); _peerTs.Clear(); _disposed = true; }
    private sealed record Options(bool Valid, int? Scale, uint? Timestamp, uint? Echo, IReadOnlyList<(uint Start, uint End)> Sacks);
    private static Options ReadOptions(TcpPacket p, ReadOnlySpan<byte> bytes)
    {
        int? scale = null; uint? ts = null, echo = null; var sacks = new List<(uint, uint)>(); bool valid = true;
        var o = bytes.Slice(p.IpLength + 20, p.TcpLength - 20);
        for (int at = 0; at < o.Length;)
        {
            byte kind = o[at]; if (kind == 0) break; if (kind == 1) { at++; continue; }
            if (at + 2 > o.Length || o[at + 1] < 2 || at + o[at + 1] > o.Length) { valid = false; break; }
            int len = o[at + 1];
            if (kind == 3) { if (len != 3 || o[at + 2] > 14 || scale is not null) valid = false; else if ((p.Flags & 2) != 0) scale = o[at + 2]; }
            if (kind == 8) { if (len != 10 || ts is not null) valid = false; else { ts = BinaryPrimitives.ReadUInt32BigEndian(o[(at + 2)..]); echo = BinaryPrimitives.ReadUInt32BigEndian(o[(at + 6)..]); } }
            if (kind == 5)
            {
                if (len < 10 || (len - 2) % 8 != 0 || sacks.Count > 0) valid = false;
                else for (int i = at + 2; i < at + len; i += 8) sacks.Add((BinaryPrimitives.ReadUInt32BigEndian(o[i..]), BinaryPrimitives.ReadUInt32BigEndian(o[(i + 4)..])));
            }
            at += len;
        }
        return valid ? new(true, scale, ts, echo, sacks) : new(false, null, null, null, []);
    }
}

// Strict bounded parser for IPv4 ICMP errors quoting an outgoing TCP header; no payload export.
public sealed record QuotedTcpError(TcpFlow Flow, uint Sequence, byte Type, byte Code, int? NextHopMtu)
{
    public static bool TryParse(ReadOnlySpan<byte> b, out QuotedTcpError? error)
    {
        error = null;
        if (b.Length < 56 || b[0] >> 4 != 4 || b[9] != 1 || BinaryPrimitives.ReadUInt16BigEndian(b[2..]) != b.Length
            || (BinaryPrimitives.ReadUInt16BigEndian(b[6..]) & 0xBFFF) != 0) return false;
        int ip = (b[0] & 15) * 4;
        if (ip < 20 || ip + 36 > b.Length || b[ip] is not (3 or 11)) return false;
        int q = ip + 8, quotedIp = (b[q] & 15) * 4;
        if (b[q] >> 4 != 4 || b[q + 9] != 6 || quotedIp < 20 || q + quotedIp + 8 > b.Length
            || BinaryPrimitives.ReadUInt16BigEndian(b[(q + 2)..]) < quotedIp + 20 || (BinaryPrimitives.ReadUInt16BigEndian(b[(q + 6)..]) & 0xBFFF) != 0
            || b[ip] == 3 && b[ip + 1] > 15 || b[ip] == 11 && b[ip + 1] > 1) return false;
        int tcp = q + quotedIp;
        ushort source = BinaryPrimitives.ReadUInt16BigEndian(b[tcp..]), dest = BinaryPrimitives.ReadUInt16BigEndian(b[(tcp + 2)..]);
        if (source == 0 || dest == 0) return false;
        int? mtu = b[ip] == 3 && b[ip + 1] == 4 ? BinaryPrimitives.ReadUInt16BigEndian(b[(ip + 6)..]) : null;
        error = new(new(PacketAddress.Read(b[(q + 12)..], false), source, PacketAddress.Read(b[(q + 16)..], false), dest),
            BinaryPrimitives.ReadUInt32BigEndian(b[(tcp + 4)..]), b[ip], b[ip + 1], mtu); return true;
    }
}
