using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public sealed record ClosedTcpPacket(DateTimeOffset Utc, bool Outbound, byte Flags, int IpBytes, int TcpHeaderBytes,
    int PayloadBytes, int? RelativeSequence, int? RelativeAck, IReadOnlyList<RelativeTcpRange> SackRanges,
    int SackBlockCount, int SackBlocksNotExported, string SackOmissionReason, double? MillisecondsFromClose,
    string Attribution, bool Ambiguous);
public sealed record ClosedTcpFlowEvidence(string Id, string FlowSha256, uint HistoricalProcessId, DateTimeOffset HistoricalBirthUtc,
    DateTimeOffset FirstSelectedUtc, DateTimeOffset? FlowCloseUtc, string LocalOriginBasis, string PeerOriginBasis,
    bool TupleReuseObserved, DateTimeOffset? ReuseObservedUtc, long MetadataDropped, bool ContextReleased,
    IReadOnlyList<ClosedTcpPacket> Packets, double? ObservedMillisecondsAfterClose = null, string ContextReleaseReason = "Live");
public sealed record RejectedTcpCopy(DateTimeOffset Utc, bool Outbound, byte Flags, int IpBytes, int TcpHeaderBytes,
    int PayloadBytes, string FlowSha256, string Reason, string Attribution = "UnassociatedRejectedCopy");
public sealed record ClosedTcpTailEvidence(IReadOnlyList<ClosedTcpFlowEvidence> Flows, IReadOnlyDictionary<string, long> Decisions,
    int TailSeconds = 8, int PreCloseSeconds = 2, int MaximumFlows = 4, int MaximumPacketsPerFlow = 32,
    bool HistoricalObservationOnly = true, bool MutationAuthorization = false, bool PacketSendApiUsed = false,
    string Scope = "Exact previously selected TCP tuple/PID/birth/endpoint history; metadata only. 2s pre-close and 8s post FLOW_CLOSE, 4 epochs/32 copies each. Reuse/SYN ambiguity suppresses relative coordinates. Missing/late events can leave residual ambiguity. NEVER current ownership proof or mutation authorization; no payload/raw tuple/sequence/endpoint exported.",
    int DiagnosticsVersion = 1, int PendingCloseSeconds = 8, IReadOnlyList<RejectedTcpCopy>? RejectedCopies = null);

// This class has no native API, no Send and NO OwnedPacket-returning resolver. It only ACCEPTS prior read-only proof.
internal sealed class ClosedTcpObservationTail : IDisposable
{
    internal const int TailSeconds = 8, PreCloseSeconds = 12, MaximumFlows = 4, MaximumPackets = 32, OpenIdleSeconds = 120, MaximumRejectedCopies = 8;
    private sealed record Copy(long Qpc, ClosedTcpPacket Packet);
    private sealed class Epoch(TcpFlow flow, OwnedPacket owner, long qpc, DateTimeOffset utc, int id)
    {
        internal readonly TcpFlow Flow = flow;
        internal readonly OwnedPacket Owner = owner;
        internal readonly long OpenQpc = qpc;
        internal long LastProof = qpc;
        internal readonly string Id = "close-tail-" + id;
        internal readonly DateTimeOffset FirstUtc = utc;
        internal readonly AionTcpTimeline Timeline = new(requireSyn: true);
        internal readonly Queue<Copy> Copies = new();
        internal long? CloseQpc, ReuseQpc;
        internal DateTimeOffset? CloseUtc, ReuseUtc;
        internal long Dropped;
        internal uint? LocalSyn, PeerSyn;
    }
    private readonly long _frequency;
    private readonly object _gate = new();
    private readonly List<Epoch> _live = [];
    private readonly List<ClosedTcpFlowEvidence> _released = [];
    private readonly Dictionary<string, long> _decisions = [];
    private readonly Queue<RejectedTcpCopy> _rejected = new();
    private int _created; private bool _disposed;
    internal ClosedTcpObservationTail(long frequency)
    { if (frequency <= 0 || frequency > 1_000_000_000) throw new ArgumentOutOfRangeException(nameof(frequency)); _frequency = frequency; }
    private void Count(string code) => _decisions[code] = _decisions.GetValueOrDefault(code) + 1;
    private static bool Same(Epoch e, OwnedPacket o) => e.Owner.Endpoint == o.Endpoint && OwnershipPolicy.SameIdentity(e.Owner.Identity, o.Identity);
    private void Reuse(Epoch e, long qpc, DateTimeOffset utc)
    {
        if (qpc < e.OpenQpc) return;
        if (e.ReuseQpc is null || qpc < e.ReuseQpc) { e.ReuseQpc = qpc; e.ReuseUtc = utc; Count("TUPLE_REUSE_OR_NEW_SYN"); }
    }
    internal void ObserveEvent(TcpFlow flow, uint pid, long? birth, ulong endpoint, int eventId, long qpc, DateTimeOffset utc, long now)
    {
        lock (_gate)
        {
            if (_disposed) return; Prune(now);
            if (eventId is 1 or 4)
            {
                foreach (var e in _live.Where(e => e.Flow == flow))
                    if (e.Owner.Endpoint != endpoint || e.Owner.Identity.ProcessId != pid || birth is long b && e.Owner.Identity.CreationTime != b) Reuse(e, qpc, utc);
                return;
            }
            if (eventId != 2) return; // FLOW_CLOSE only, not SOCKET_CLOSE.
            var matches = _live.Where(e => e.Flow == flow && e.Owner.Endpoint == endpoint && e.Owner.Identity.ProcessId == pid
                && (birth is null || e.Owner.Identity.CreationTime == birth) && qpc >= e.OpenQpc
                && (e.CloseQpc is null || qpc <= e.CloseQpc)).ToArray();
            if (matches.Length != 1) { Count("CLOSE_HISTORY_MISSING_OR_AMBIGUOUS"); return; }
            var closed = matches[0];
            if (closed.CloseQpc is null) { closed.CloseQpc = qpc; closed.CloseUtc = utc; Count("FLOW_CLOSE_MATCHED"); }
        }
    }
    internal void ObserveSelected(TcpPacket packet, ReadOnlySpan<byte> bytes, OwnedPacket owner, bool outbound, long qpc, DateTimeOffset utc, long now)
    {
        lock (_gate)
        {
            if (_disposed) return; Prune(now);
            var flow = outbound ? packet.Flow : packet.Flow.Reverse();
            if (owner.Endpoint == 0)
            {
                // A table entry can briefly outlive FLOW_CLOSE. It cannot restore the deleted endpoint history.
                foreach (var prior in _live.Where(e => e.Flow == flow && !OwnershipPolicy.SameIdentity(e.Owner.Identity, owner.Identity))) Reuse(prior, qpc, utc);
                Count("CURRENT_TABLE_WITHOUT_ENDPOINT_OBSERVATION_ONLY");
                ObserveUnowned(packet, bytes, outbound, qpc, utc, now); return;
            }
            var e = _live.LastOrDefault(e => e.Flow == flow && Same(e, owner) && e.CloseQpc is null);
            e ??= _live.LastOrDefault(e => e.Flow == flow && Same(e, owner) && e.CloseQpc is long close && qpc <= close);
            foreach (var other in _live.Where(e => e.Flow == flow && !Same(e, owner))) Reuse(other, qpc, utc);
            // Closed history is never re-opened by a fresh table proof; that is a separate epoch.
            if (e is null)
            {
                foreach (var prior in _live.Where(e => e.Flow == flow)) Reuse(prior, qpc, utc);
                if (_created == MaximumFlows) { Count("FLOW_EPOCH_LIMIT"); return; }
                e = new(flow, owner, qpc, utc, ++_created); _live.Add(e);
            }
            if (qpc < e.OpenQpc) { Count("CAPTURE_BEFORE_PROOF"); return; }
            e.LastProof = Math.Max(e.LastProof, qpc);
            Add(e, packet, bytes, outbound, qpc, utc, "CurrentSelectedReadOnly");
        }
    }
    internal void ObserveUnowned(TcpPacket packet, ReadOnlySpan<byte> bytes, bool outbound, long qpc, DateTimeOffset utc, long now)
    {
        lock (_gate)
        {
            if (_disposed) return; Prune(now);
            var flow = outbound ? packet.Flow : packet.Flow.Reverse();
            var histories = _live.Where(e => e.Flow == flow && qpc >= e.OpenQpc
                && (e.CloseQpc is long closed ? qpc <= closed + TailSeconds * _frequency : qpc <= e.LastProof + OpenIdleSeconds * _frequency)).ToArray();
            if (histories.Length == 0)
            {
                Count("UNOWNED_NO_LIVE_EXACT_HISTORY");
                string sha = TcpFlowFingerprint.Flow(flow);
                string reason = _live.Any(e => e.Flow == flow && qpc < e.OpenQpc) ? "CAPTURE_BEFORE_CURRENT_PROOF"
                    : _released.Any(e => e.FlowSha256 == sha) ? "EXPIRED_CONTEXT_NO_ATTRIBUTION" : "NO_EXACT_CURRENT_HISTORY";
                Count(reason);
                if (_rejected.Count == MaximumRejectedCopies) { _rejected.Dequeue(); Count("REJECTED_COPY_METADATA_EVICTED"); }
                // Filtered target-tuple metadata, NOT proof of its process/epoch; no relative coordinates or PID.
                _rejected.Enqueue(new(utc, outbound, packet.Flags, packet.TotalLength, packet.TcpLength, packet.PayloadLength, sha, reason));
                return;
            }
            foreach (var e in histories)
            {
                if (histories.Length > 1 || (packet.Flags & 2) != 0 && e.CloseQpc is not null) Reuse(e, qpc, utc);
                if (e.CloseQpc is null) Count("OPEN_HISTORY_OBSERVATION_ONLY");
                Add(e, packet, bytes, outbound, qpc, utc, e.CloseQpc is null ? "HistoricalPendingCloseReadOnly" : "HistoricalClosedReadOnly");
            }
        }
    }
    private void Add(Epoch e, TcpPacket packet, ReadOnlySpan<byte> bytes, bool outbound, long qpc, DateTimeOffset utc, string attribution)
    {
        if ((packet.Flags & 2) != 0)
        {
            var previous = outbound ? e.LocalSyn : e.PeerSyn;
            if (previous is uint seq && seq != packet.Sequence) Reuse(e, qpc, utc);
            if (outbound) e.LocalSyn ??= packet.Sequence; else e.PeerSyn ??= packet.Sequence;
        }
        // Header-only projection: never pass payload to timeline hashing or retain a raw packet.
        e.Timeline.Observe(packet with { TotalLength = packet.PayloadOffset }, bytes[..packet.PayloadOffset], outbound, utc);
        var d = e.Timeline.Snapshot(); var m = d.FirstEvents.Concat(d.RecentEvents).Last(m => m.Utc == utc && m.Outbound == outbound && m.Flags == packet.Flags);
        var copy = new ClosedTcpPacket(utc, outbound, packet.Flags, packet.TotalLength, packet.TcpLength, packet.PayloadLength,
            m.RelativeSequence, m.RelativeAck, m.SackRanges, m.SackBlockCount, m.SackBlocksNotExported, m.SackOmissionReason,
            null, attribution, false);
        if (e.Copies.Count == MaximumPackets) { e.Copies.Dequeue(); e.Dropped++; }
        e.Copies.Enqueue(new(qpc, copy)); Count("METADATA_COPY_RECORDED");
    }
    private ClosedTcpFlowEvidence Export(Epoch e, bool released, long now, string reason = "Live")
    {
        var d = e.Timeline.Snapshot();
        var packets = e.Copies.OrderBy(c => c.Qpc).Where(c => e.CloseQpc is not long close
            || c.Qpc >= close - PreCloseSeconds * _frequency && c.Qpc <= close + TailSeconds * _frequency).Select(c =>
        {
            bool ambiguous = e.ReuseQpc is long reuse && c.Qpc >= reuse;
            return c.Packet with
            {
                MillisecondsFromClose = e.CloseQpc is long q ? (c.Qpc - q) * 1000d / _frequency : null,
                Attribution = ambiguous ? "AmbiguousTupleReuse" : c.Packet.Attribution,
                Ambiguous = ambiguous,
                RelativeSequence = ambiguous ? null : c.Packet.RelativeSequence,
                RelativeAck = ambiguous ? null : c.Packet.RelativeAck,
                SackRanges = ambiguous ? [] : c.Packet.SackRanges,
                SackBlocksNotExported = ambiguous ? c.Packet.SackBlockCount : c.Packet.SackBlocksNotExported,
                SackOmissionReason = ambiguous && c.Packet.SackBlockCount > 0 ? "OriginUnknown" : ambiguous ? "None" : c.Packet.SackOmissionReason
            };
        }).ToArray();
        return new(e.Id, TcpFlowFingerprint.Flow(e.Flow), e.Owner.Identity.ProcessId, DateTimeOffset.FromFileTime(e.Owner.Identity.CreationTime).ToUniversalTime(),
            e.FirstUtc, e.CloseUtc, d.LocalOriginBasis, d.PeerOriginBasis, e.ReuseQpc is not null, e.ReuseUtc, e.Dropped, released, packets,
            e.CloseQpc is long end ? Math.Clamp((now - end) * 1000d / _frequency, 0, 8000) : null, reason);
    }
    private void Prune(long now)
    {
        foreach (var e in _live.Where(e => e.CloseQpc is long close ? now > close + TailSeconds * _frequency : now > e.LastProof + OpenIdleSeconds * _frequency).ToArray())
        { _released.Add(Export(e, true, now, e.CloseQpc is null ? "IdleExpired" : "TailExpired")); e.Timeline.Dispose(); _live.Remove(e); Count("HISTORICAL_CONTEXT_RELEASED"); }
    }
    internal ClosedTcpTailEvidence Snapshot(long now)
    {
        lock (_gate)
        {
            if (!_disposed) Prune(now);
            return new(_released.Concat(_live.Select(e => Export(e, false, now))).OrderBy(e => e.FirstSelectedUtc).ToArray(), new Dictionary<string, long>(_decisions),
                PreCloseSeconds: PreCloseSeconds, DiagnosticsVersion: 2, PendingCloseSeconds: OpenIdleSeconds, RejectedCopies: _rejected.ToArray(),
                Scope: "Exact previously proven tuple/PID/birth history ONLY for read-only observation. Pending CLOSE: 120s since last CURRENT proof; historic copies NEVER refresh TTL. Window 12s pre/8s post FLOW_CLOSE, 4 epochs/32 metadata copies. Rejected target-filter copies are unassociated, not process or epoch proof. Reuse suppresses relative coordinates. Missing events/overflow remain explicit limitations. No payload/raw tuple/sequence/endpoint and NEVER mutation authorization.");
        }
    }
    internal void Stop(long now)
    { lock (_gate) { if (_disposed) return; foreach (var e in _live) { _released.Add(Export(e, true, now, "RecorderStopped")); e.Timeline.Dispose(); } _live.Clear(); _disposed = true; } }
    public void Dispose() => Stop(System.Diagnostics.Stopwatch.GetTimestamp());
}
