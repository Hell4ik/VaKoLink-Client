using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

// Offline only: inputs are already sanitized captures. Never loads a native engine or sends packets.
public enum GameObservationLeg { Unknown, DirectSelectedNetwork, TunClientFacing }
public sealed record ObservedTcpRange(DateTimeOffset Utc, int Start, int End, string Relation);
public sealed record ObservedAckProgress(DateTimeOffset Utc, int Offset);
public sealed record AionCaptureAnalysis(string Id, string? FlowSha256, string ImageSha256, string Ownership,
    GameObservationLeg Leg, IReadOnlyList<uint> Interfaces, long OutboundBytes, long InboundBytes,
    int MaximumAck, int ObservedPrefix, int UnacknowledgedBytes, bool TrackingLimited,
    bool ObservedAckCrossed556Range, bool RemoteServerAcceptanceProven, bool CompleteDetailedTimeline,
    IReadOnlyList<ObservedAckProgress> AckProgress, ObservedTcpRange? FirstRangeAtFinalAck,
    IReadOnlyList<ObservedTcpRange> RangesCovering556, IReadOnlyList<ObservedTcpRange> Overlaps,
    DateTimeOffset? LastAckProgressUtc, DateTimeOffset? LastIncomingUtc, DateTimeOffset? FlowCloseUtc,
    int? MinimumPeerWindow, long TimelineDropped,
    bool? SmallBoundaryCoverageComplete, long? ReplacedOriginals, long? SegmentsSent, long? AfterCopies,
    string Limitation);
public sealed record AionObservationComparison(bool SameLogicalDestination, bool SameImage,
    bool SameObservationLeg, bool SameInterfaceIndexes, bool SameStreamBytesProven,
    bool EarlyPacketMetadataComparable, string Conclusion);

public static class AionCaptureComparison
{
    public static bool IsTarget(GameConnectionEvidence c) => c.Protocol == "TCP" && c.AddressFamily == "IPv4"
        && c.RemotePort == AionTcpSegmentation.TargetPort && c.RemoteAddressSha256 == AionTcpSegmentation.TargetAddressSha256
        && c.ComponentFileName == "AION2.exe" && c.ImageSha256 == AionTcpSegmentation.ClientImageSha256 && c.Transport is not null;

    public static AionCaptureAnalysis Analyze(GameConnectionEvidence c, GameObservationLeg leg, AionSegmentEvidence? active = null)
    {
        if (!IsTarget(c) || !Enum.IsDefined(leg)) throw new ArgumentException("AION_COMPARISON_SCOPE_INVALID");
        var t = c.Transport!;
        var detail = c.Detail;
        var events = detail is null ? [] : detail.FirstEvents.Concat(detail.RecentEvents).OrderBy(e => e.Utc).ToArray();
        bool complete = detail is not null && detail.TimelineDropped == 0 && events.LongLength == detail.TotalEvents
            && detail.LocalOriginBasis != "Unknown";
        var progress = new List<ObservedAckProgress>(); int ack = -1;
        foreach (var e in events)
            if (!e.Outbound && e.RelativeAck is int next && next > ack) { progress.Add(new(e.Utc, next)); ack = next; }
        var ranges = events.Where(e => e.Outbound && e.PayloadBytes > 0 && e.RelativeSequence is >= 0)
            .Select(e => new ObservedTcpRange(e.Utc, e.RelativeSequence!.Value, checked(e.RelativeSequence.Value + e.PayloadBytes), e.RangeRelation)).ToArray();
        var first = complete && t.LastAckProgressUtc is DateTimeOffset last
            ? ranges.FirstOrDefault(e => e.Utc > last && e.Start == t.MaximumAcknowledgedOffset) : null;
        var windows = events.Where(e => !e.Outbound && (e.Flags & 2) == 0 && e.EffectiveWindow is not null).Select(e => e.EffectiveWindow!.Value).ToArray();
        var flow = active?.Flows.SingleOrDefault(f => c.FlowSha256 is not null && f.FlowSha256 == c.FlowSha256 && f.ProcessId == c.ProcessId
            && f.RemoteAddressSha256 == c.RemoteAddressSha256 && f.RemotePort == c.RemotePort && f.ComponentFileName == c.ComponentFileName);
        // Total send counters plus complete before timeline, not just an after maximum. After is not physical wire proof.
        bool? covered = active?.StrategyId == AionSmallBoundarySplit.StrategyId ? complete && flow is not null
            && active.SendFailures == 0 && active.PartialFallbacks == 0 && active.UnforwardedOriginals == 0
            && active.PassedOriginals == 0 && active.StreamChecksPassed && active.NoFakePackets
            && active.Failure is null && flow.OriginalsReplaced == events.LongCount(e => e.Outbound && e.PayloadBytes == 11)
            && flow.OriginalsReplaced > 0 && flow.SegmentsSent == flow.OriginalsReplaced * 2
            && flow.MaximumSentPayload == 10 && flow.AfterCopies == flow.SegmentsSent && flow.AfterMaximumPayload == 10 : null;
        return new(c.Id, c.FlowSha256, c.ImageSha256, c.OwnershipEvidence, leg, c.InterfaceIndexes ?? [], c.OutboundBytes,
            c.InboundBytes, t.MaximumAcknowledgedOffset, t.ContiguousObservedPayloadBytes, t.UnacknowledgedContiguousBytes,
            t.TrackingLimited, t.MaximumAcknowledgedOffset >= 567 && t.ContiguousObservedPayloadBytes >= 567,
            false, complete, progress, first, ranges.Where(e => e.Start <= 556 && e.End >= 567).ToArray(),
            ranges.Where(e => e.Relation == "Overlap").ToArray(), t.LastAckProgressUtc, c.LastInboundUtc, c.FlowCloseObservedUtc,
            windows.Length > 0 ? windows.Min() : null, detail?.TimelineDropped ?? c.ActivityDropped, covered,
            flow?.OriginalsReplaced, flow?.SegmentsSent, flow?.AfterCopies,
            "Relative ranges are per connection, not matching payload across attempts. ACK concerns the observed leg, not application acceptance. "
            + "A limited old tracker cannot establish zero retransmissions or zero outstanding bytes at capture end. "
            + "Capture is not physical wire; no proof of loss location, DPI or remote ACK origin.");
    }

    public static AionObservationComparison Compare(GameConnectionEvidence a, GameObservationLeg aLeg,
        GameConnectionEvidence b, GameObservationLeg bLeg)
    {
        var x = Analyze(a, aLeg); var y = Analyze(b, bLeg);
        bool sameLeg = aLeg != GameObservationLeg.Unknown && aLeg == bLeg;
        bool sameInterfaces = x.Interfaces.Count > 0 && x.Interfaces.Order().SequenceEqual(y.Interfaces.Order());
        return new(a.RemoteAddressSha256 == b.RemoteAddressSha256 && a.RemotePort == b.RemotePort && a.AddressFamily == b.AddressFamily,
            a.ImageSha256 == b.ImageSha256, sameLeg, sameInterfaces, false,
            sameLeg && sameInterfaces && x.CompleteDetailedTimeline && y.CompleteDetailedTimeline,
            "Same logical destination does not establish same transport termination or path. Existing VPN success is valid game evidence, "
            + "but its client-facing ACK is not a remote-server ACK control. A missing early timeline cannot be reconstructed from lifetime totals or a recent tail.");
    }
}
