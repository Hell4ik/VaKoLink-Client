using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public sealed record PassiveWireEvent(long Order, long CaptureQpc, DateTimeOffset CapturedUtc, string Point,
    bool Outbound, bool Impostor, byte Flags, int PayloadBytes, int? RelativeSequence, int? RelativeAck,
    string PayloadRelation, string TimestampRelation, byte HopLimit, int ComparedOriginalBytes,
    int? TimestampDelta, string TlsPrefixKind, int? TlsDeclaredRecordBytes);
public sealed record PassiveWireFlow(string FlowSha256, uint ProcessId, long ProcessBirthFileTimeUtc,
    string RemoteAddressSha256, ushort RemotePort, string AddressFamily, TlsSniEvidence? OriginalSni,
    int OriginalContiguousBytes, int? FirstRecordBytes, int? SniStart, int? SniEnd,
    IReadOnlyList<PassiveWireEvent> Events, long EventsDropped);
public sealed record PassiveWireEvidence(IReadOnlyList<PassiveWireFlow> Flows, long FlowsDropped,
    string Limits = "32 approved flows, first 96 events per flow; first ClientHello <=16384 bytes, 30s non-resetting assembly deadline. No payload/absolute sequence exported. Worker order is not wire order; use capture QPC. AFTER differences suggest injection/modification, not exact engine rule execution or application delivery.");

// Diagnostic only: never grants ownership and never calls a packet send API.
public sealed class PassiveWireTrace : IDisposable
{
    public const int MaximumFlows = 32, MaximumEvents = 96, MaximumRecord = 16384;
    private readonly object _gate = new();
    private readonly Dictionary<string, Flow> _flows = new();
    private long _order, _dropped;
    private PassiveWireEvidence? _final;
    private sealed record Event(long Order, long Qpc, DateTimeOffset Utc, bool Before, bool Outbound, bool Impostor,
        byte Flags, uint Sequence, uint Ack, int Bytes, byte[] Copy, uint? Timestamp, byte HopLimit,
        string TlsPrefixKind, int? TlsDeclaredRecordBytes);
    private sealed class Flow
    {
        internal required TcpFlow Tuple;
        internal required ProcessIdentity Identity;
        internal readonly List<Event> Events = [];
        internal readonly byte[] Record = new byte[MaximumRecord];
        internal readonly bool[] Present = new bool[MaximumRecord];
        internal uint? ClientBase, ServerBase;
        internal DateTimeOffset? Started;
        internal int Contiguous;
        internal long Dropped;
        internal string? Host;
        internal int? RecordBytes, SniStart, SniEnd;
    }
    public void Observe(TcpPacket packet, ReadOnlySpan<byte> bytes, OwnedPacket owner, bool outbound,
        bool before, bool impostor, long qpc, DateTimeOffset utc)
    {
        lock (_gate)
        {
            if (_final is not null) return;
            var tuple = outbound ? packet.Flow : packet.Flow.Reverse();
            var key = TcpFlowFingerprint.Flow(tuple);
            if (!_flows.TryGetValue(key, out var flow))
            {
                if (_flows.Count >= MaximumFlows) { _dropped++; return; }
                flow = new() { Tuple = tuple, Identity = owner.Identity }; _flows.Add(key, flow);
            }
            // A tuple reuse may not inherit another process's bytes.
            if (flow.Identity != owner.Identity) { flow.Dropped++; return; }
            if (before && !impostor && (packet.Flags & 2) != 0)
            {
                if (outbound) flow.ClientBase ??= unchecked(packet.Sequence + 1);
                else flow.ServerBase ??= unchecked(packet.Sequence + 1);
            }
            var payload = bytes.Slice(packet.PayloadOffset, packet.PayloadLength);
            if (before && outbound && !impostor && !payload.IsEmpty)
            {
                if (payload[0] == 22 && (payload.Length < 2 || payload[1] == 3) && (payload.Length < 6 || payload[5] == 1))
                { flow.ClientBase ??= packet.Sequence; flow.Started ??= utc; }
                if (flow.Started is { } start && utc >= start && utc - start < TimeSpan.FromSeconds(30)
                    && flow.ClientBase is { } anchor)
                {
                    int offset = unchecked((int)(packet.Sequence - anchor));
                    if (offset >= 0 && offset < MaximumRecord)
                    {
                        int take = Math.Max(0, Math.Min(payload.Length, (flow.RecordBytes ?? MaximumRecord) - offset));
                        for (int i = 0; i < take; i++)
                            if (!flow.Present[offset + i]) { flow.Record[offset + i] = payload[i]; flow.Present[offset + i] = true; }
                        while (flow.Contiguous < MaximumRecord && flow.Present[flow.Contiguous]) flow.Contiguous++;
                        ParseHost(flow);
                    }
                }
            }
            if (flow.Events.Count >= MaximumEvents) { flow.Dropped++; return; }
            uint? ts = TcpTimestampOptions.TryRead(bytes, packet, out _, out var timestamp, out _) ? timestamp : null;
            // Volatile memory only; cleared at stop. Inbound application bytes are never retained.
            var copy = outbound ? payload[..Math.Min(payload.Length, MaximumRecord)].ToArray() : [];
            string tls = payload.Length >= 6 && payload[1] == 3 ? payload[0] switch
            { 22 when payload[5] == 1 => "CLIENT_HELLO", 22 when payload[5] == 2 => "SERVER_HELLO", 21 => "ALERT", 23 => "ENCRYPTED", _ => "OTHER" } : "NO_RECOGNIZED_PREFIX";
            int? declared = tls != "NO_RECOGNIZED_PREFIX" && tls != "OTHER" ? 5 + BinaryPrimitives.ReadUInt16BigEndian(payload[3..]) : null;
            flow.Events.Add(new(++_order, qpc, utc, before, outbound, impostor, packet.Flags, packet.Sequence,
                packet.Acknowledgment, packet.PayloadLength, copy, ts, bytes[packet.IsV6 ? 7 : 8], tls, declared));
        }
    }
    private static void ParseHost(Flow flow)
    {
        var bytes = flow.Record.AsSpan(0, flow.Contiguous);
        if (bytes.Length < 9 || bytes[0] != 22 || bytes[1] != 3 || bytes[5] != 1) return;
        int record = 5 + BinaryPrimitives.ReadUInt16BigEndian(bytes[3..]);
        if (record > MaximumRecord) return;
        flow.RecordBytes = record;
        flow.Contiguous = Math.Min(flow.Contiguous, record);
        if (bytes.Length < record || !TlsClientHelloSplit.TryFindSplit(bytes[..record], out int split, out _, out _, true)) return;
        // Find the SNI range structurally: never search for a guessed hostname.
        int at = 43; if (at >= record) return; at += 1 + bytes[at];
        if (at + 2 > record) return; at += 2 + BinaryPrimitives.ReadUInt16BigEndian(bytes[at..]);
        if (at >= record) return; at += 1 + bytes[at]; at += 2;
        while (at + 4 <= record)
        {
            int type = BinaryPrimitives.ReadUInt16BigEndian(bytes[at..]);
            int count = BinaryPrimitives.ReadUInt16BigEndian(bytes[(at + 2)..]); at += 4;
            if (count > record - at) return;
            if (type == 0)
            {
                if (count < 6) return;
                int length = BinaryPrimitives.ReadUInt16BigEndian(bytes[(at + 3)..]);
                if (length + 5 != count || split != at + 5 + Math.Max(1, length / 2)) return;
                flow.SniStart = at + 5; flow.SniEnd = at + 5 + length;
                flow.Host = Encoding.ASCII.GetString(bytes.Slice(at + 5, length)); return;
            }
            at += count;
        }
    }
    internal ReferenceFlowDecision? Project(string hash, ReferenceConfiguration configuration)
    {
        lock (_gate) return _flows.TryGetValue(hash, out var flow) && flow.Host is { } host
            ? configuration.Evaluate(flow.Tuple, TlsSniEvidence.FromHost(host), host) : null;
    }
    public PassiveWireEvidence Snapshot()
    {
        lock (_gate) return _final ?? new(_flows.Select(pair => Export(pair.Key, pair.Value)).ToArray(), _dropped);
    }
    private static int? Relative(uint value, uint? anchor)
    {
        if (anchor is null) return null;
        int delta = unchecked((int)(value - anchor.Value));
        return delta is >= -1 and <= 1_048_576 ? delta : null;
    }
    private static PassiveWireFlow Export(string hash, Flow flow)
    {
        var events = flow.Events.Select(e =>
        {
            var offset = Relative(e.Sequence, e.Outbound ? flow.ClientBase : flow.ServerBase);
            var ack = (e.Flags & 16) != 0 ? Relative(e.Ack, e.Outbound ? flow.ServerBase : flow.ClientBase) : null;
            string relation = e.Bytes == 0 ? "NO_PAYLOAD" : !e.Outbound ? "INBOUND_NOT_RETAINED" : "BASELINE_RANGE_UNAVAILABLE";
            int compared = 0;
            if (e.Outbound && e.Bytes > 0 && offset is >= 0 && offset < flow.Contiguous)
            {
                compared = Math.Min(e.Copy.Length, flow.Contiguous - offset.Value);
                bool same = e.Copy.AsSpan(0, compared).SequenceEqual(flow.Record.AsSpan(offset.Value, compared));
                relation = compared == e.Bytes ? same ? "MATCHES_ORIGINAL_RANGE" : "DIFFERS_FROM_ORIGINAL_RANGE"
                    : same ? "MATCHES_KNOWN_PREFIX_ONLY" : "DIFFERS_IN_KNOWN_PREFIX";
            }
            var original = flow.Events.FirstOrDefault(other => other.Before && other.Outbound && !other.Impostor
                && other.Bytes > 0 && offset is not null && Relative(other.Sequence, flow.ClientBase) is { } otherOffset
                && offset >= otherOffset && offset < otherOffset + other.Bytes);
            string ts = e.Timestamp is null ? "ABSENT" : original?.Timestamp is not { } baseline ? "BASELINE_UNAVAILABLE"
                : e.Timestamp.Value == baseline ? "SAME_AS_ORIGINAL" : unchecked((int)(e.Timestamp.Value - baseline)) < 0 ? "OLDER_THAN_ORIGINAL" : "NEWER_THAN_ORIGINAL";
            int? delta = e.Timestamp is { } tick && original?.Timestamp is { } otherTick ? unchecked((int)(tick - otherTick)) : null;
            if (delta is < -3_000_000 or > 3_000_000) delta = null;
            return new PassiveWireEvent(e.Order, e.Qpc, e.Utc, e.Before ? "BEFORE" : "AFTER", e.Outbound,
                e.Impostor, e.Flags, e.Bytes, offset, ack, relation, ts, e.HopLimit, compared, delta, e.TlsPrefixKind, e.TlsDeclaredRecordBytes);
        }).ToArray();
        return new(hash, flow.Identity.ProcessId, flow.Identity.CreationTime, TcpFlowFingerprint.RemoteAddress(flow.Tuple),
            flow.Tuple.RemotePort, flow.Tuple.Local.V6 ? "IPv6" : "IPv4", flow.Host is { } host ? TlsSniEvidence.FromHost(host) : null,
            flow.Contiguous, flow.RecordBytes, flow.SniStart, flow.SniEnd, events, flow.Dropped);
    }
    public void Dispose()
    {
        lock (_gate)
        {
            _final ??= new(_flows.Select(pair => Export(pair.Key, pair.Value)).ToArray(), _dropped);
            foreach (var flow in _flows.Values)
            {
                CryptographicOperations.ZeroMemory(flow.Record);
                foreach (var e in flow.Events) CryptographicOperations.ZeroMemory(e.Copy);
                flow.Host = null;
            }
            _flows.Clear();
        }
    }
}
