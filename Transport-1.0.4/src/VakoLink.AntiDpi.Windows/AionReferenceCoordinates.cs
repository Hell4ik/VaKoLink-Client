using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public sealed record AionReferenceCoordinates(string FlowSha256, uint ProcessId, int TransportAck,
    string TransportOriginBasis, int? FirstPayloadOffsetFromSyn, int? MaximumSynAnchoredAck, long TimelineDropped,
    string Scope = "Transport starts at first outbound payload, including injected copies; Detail uses SYN when observed. Different origins are not byte loss. SYN ACK maximum is retained-events-only if timeline dropped.")
{
    public static IReadOnlyList<AionReferenceCoordinates> From(GamePassiveEvidence evidence) => evidence.Connections
        .Where(c => c.FlowSha256 is not null && c.Transport is not null && c.Detail is not null).Select(c =>
        {
            var detail = c.Detail!; var events = detail.FirstEvents.Concat(detail.RecentEvents).OrderBy(e => e.Utc).ToArray();
            bool syn = detail.LocalOriginBasis is "LocalSyn" or "PeerSynAck";
            var first = events.FirstOrDefault(e => e.Outbound && e.PayloadBytes > 0);
            var acks = events.Where(e => !e.Outbound && e.RelativeAck is not null).Select(e => e.RelativeAck!.Value).ToArray();
            return new AionReferenceCoordinates(c.FlowSha256!, c.ProcessId, c.Transport!.MaximumAcknowledgedOffset,
                c.Transport.OriginBasis, syn ? first?.RelativeSequence : null,
                syn && acks.Length > 0 ? acks.Max() : null, detail.TimelineDropped,
                Scope: c.Transport.OriginBasis == "FirstOutboundPayloadIncludingInjected"
                    ? "Transport starts at first outbound payload, including injected copies; Detail uses SYN when observed. Different origins are not byte loss. SYN ACK maximum is retained-events-only if timeline dropped."
                    : "Reference Transport and Detail require SYN/SYN-ACK origins. Synthetic/pre-origin payload excluded from real ranges. Unknown origins remain unknown, not rebased on payload. Retained-events-only detailed ACK if timeline dropped.");
        }).ToArray();
}
