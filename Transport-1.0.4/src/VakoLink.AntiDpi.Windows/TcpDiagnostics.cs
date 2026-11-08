using System.Diagnostics;
using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public sealed record TcpOriginalDecision(DateTimeOffset CapturedUtc, string RangeRelation, int? RelativeSequence,
    int PayloadBytes, string PrefixDecision, string Decision, int RealSegmentsSent, bool ReplacementCompleted, bool TlsFakeSent = false, TlsHostRange? StructuralHostRange = null);

public sealed record TcpConnectionEvidence(string Id, string ProfileId, string AddressFamily, string OwnershipEvidence,
    long OutboundPackets, long InboundPackets, long Syn, long SynAck, long Reset, long Fin,
    long ClientHello, long ServerHello, long PlaintextAlert, long EncryptedRecords,
    DateTimeOffset? FirstOutboundUtc, DateTimeOffset? LastOutboundUtc, DateTimeOffset? FirstInboundUtc, DateTimeOffset? LastInboundUtc,
    string ClientHelloClassification, long SplitOriginals, long SplitSegments, string LastSplitDecision, uint? LastTcpState,
    uint ProcessId = 0, DateTimeOffset? CreationUtc = null, string? ComponentFileName = null, string? VersionDirectory = null,
    IReadOnlyDictionary<string, long>? DecisionCounts = null, TlsSniEvidence? Sni = null,
    long InboundPayloadPackets = 0, long InboundPayloadBytes = 0, DateTimeOffset? FirstInboundPayloadUtc = null,
    DateTimeOffset? LastInboundPayloadUtc = null, long TlsFakePackets = 0, TcpHandshakeProgress? HandshakeProgress = null,
    IReadOnlyList<TcpOriginalDecision>? OriginalDecisionTrace = null, long DecisionTraceDropped = 0,
    long InboundReset = 0, long OutboundReset = 0, long InboundFin = 0, long OutboundFin = 0, bool? EchExtensionObserved = null,
    ushort RemotePort = 0, string? RemoteAddressSha256 = null, string? FlowSha256 = null, bool? TcpTimestampOptionObserved = null,
    long InboundImpostorCopies = 0, long OutboundImpostorCopies = 0, bool? ServerHelloPrefixReassembled = null, bool? TcpTimestampPeerEchoObserved = null);
public sealed record TcpDiagnosticSnapshot(DateTimeOffset CapturedUtc, IReadOnlyList<TcpConnectionEvidence> Connections,
    long UnknownCopies, long ConnectionsDropped, long TableProbeFailures, bool ObserverEnabled, bool DrainConfirmed,
    string Limitation = "TLS metadata only; encrypted HTTP/WebSocket/application success cannot be inferred. Current-table copies are not mutation authorization.",
    IReadOnlyDictionary<string, long>? OwnershipResolutionCalls = null, IReadOnlyList<TcpComponentObservation>? ComponentEvents = null,
    IReadOnlyDictionary<string, long>? CaptureHealth = null);

public sealed class TcpDiagnosticCollector
{
    private readonly object _gate = new();
    private readonly Dictionary<(TcpFlow, string, long), TcpConnectionEvidence> _entries = new();
    private readonly Dictionary<(TcpFlow, string, long), TlsPrefixAssembler> _prefixes = new();
    private readonly Dictionary<(TcpFlow, string, long), TlsExtensionObserver> _extensions = new();
    private readonly Dictionary<(TcpFlow, string, long), TlsFirstRecordObserver> _serverPrefixes = new();
    private readonly Dictionary<string, long> _health = new();
    private readonly Dictionary<(TcpFlow Flow, string Profile, long Birth, ulong Endpoint), TcpHandshakeTracker> _handshakes = new();
    private readonly long _started = Stopwatch.GetTimestamp();
    private long _unknown, _dropped, _probeFailures;
    private bool _enabled, _drained;
    public void Start(bool observerEnabled) { lock (_gate) _enabled = observerEnabled; }
    public void Stop(bool drained) { lock (_gate) { _drained = drained; foreach (var prefix in _prefixes.Values) prefix.Dispose(); _prefixes.Clear(); foreach (var tracker in _handshakes.Values) tracker.Dispose(); _handshakes.Clear(); foreach (var observer in _extensions.Values) observer.Dispose(); _extensions.Clear(); foreach (var prefix in _serverPrefixes.Values) prefix.Dispose(); _serverPrefixes.Clear(); } }
    internal void ObserveCapture(bool parsed, bool outbound, bool impostor)
    {
        lock (_gate)
        {
            var direction = outbound ? "OUTBOUND_" : "INBOUND_";
            foreach (var suffix in new[] { "CAPTURED", parsed ? "PARSED" : "PARSE_REJECTED", impostor ? "IMPOSTOR" : "NONIMPOSTOR" })
            { var key = direction + suffix; _health[key] = _health.GetValueOrDefault(key) + 1; }
        }
    }

    internal (string Relation, int? RelativeSequence) ObserveDivertedOriginal(TcpPacket packet, ReadOnlySpan<byte> payload, OwnedPacket owner)
    {
        lock (_gate)
        {
            var key = (packet.Flow, owner.Profile.Id, owner.Identity.CreationTime);
            var entry = Get(key, owner.Evidence); if (entry is null) return ("CONNECTION_EVIDENCE_LIMIT", null);
            var trackerKey = (packet.Flow, owner.Profile.Id, owner.Identity.CreationTime, owner.Endpoint);
            if (!_handshakes.TryGetValue(trackerKey, out var tracker))
            {
                if (_handshakes.Count >= 64) return ("HANDSHAKE_TRACKER_LIMIT", null);
                tracker = new TcpHandshakeTracker(); _handshakes.Add(trackerKey, tracker);
            }
            var relation = tracker.ObserveOriginal(packet.Sequence, payload);
            _entries[key] = entry with { HandshakeProgress = tracker.Snapshot() }; return relation;
        }
    }
    internal void Copy(TcpPacket packet, ReadOnlySpan<byte> bytes, OwnedPacket? owner, bool outbound, long captureQpc, bool impostor = false)
    {
        lock (_gate)
        {
            if (owner is null) { _unknown++; return; }
            var key = (outbound ? packet.Flow : packet.Flow.Reverse(), owner.Profile.Id, owner.Identity.CreationTime);
            var entry = Get(key, owner.Evidence);
            if (entry is null) return;
            var utc = DateTimeOffset.UtcNow - TimeSpan.FromSeconds(Math.Clamp((Stopwatch.GetTimestamp() - captureQpc) / (double)Stopwatch.Frequency, 0, 1200));
            var payload = bytes[packet.PayloadOffset..];
            bool timestampSample = outbound && payload.Length > 0 && !impostor;
            bool timestamps = TcpTimestampOptions.TryRead(bytes, packet, out _, out _, out var timestampEcho);
            var server = entry.ServerHelloPrefixReassembled;
            if (!outbound && payload.Length > 0 && server is null)
            {
                if (!_serverPrefixes.TryGetValue(key, out var prefix)) { prefix = new TlsFirstRecordObserver(); _serverPrefixes.Add(key, prefix); }
                prefix.Observe(packet.Sequence, payload, Stopwatch.GetElapsedTime(_started)); server = prefix.ServerHelloPrefix;
            }
            var ech = entry.EchExtensionObserved;
            if (outbound && !impostor && payload.Length > 0 && ech is null)
            {
                if (!_extensions.TryGetValue(key, out var observer) && payload[0] == 22)
                { observer = new TlsExtensionObserver(); _extensions.Add(key, observer); }
                if (observer is not null) { observer.Observe(packet.Sequence, payload, Stopwatch.GetElapsedTime(_started)); ech = observer.EchExtensionObserved; }
            }
            var progress = entry.HandshakeProgress;
            if (!outbound && (packet.Flags & 0x10) != 0 && _handshakes.TryGetValue((key.Item1, key.Item2, key.Item3, owner.Endpoint), out var tracker))
            { tracker.ObservePeerAck(packet.Acknowledgment); progress = tracker.Snapshot(); }
            bool hello = payload.Length >= 9 && payload[0] == 22 && payload[1] == 3;
            var classification = entry.ClientHelloClassification;
            var sni = entry.Sni;
            if (outbound && !impostor && hello && payload[5] == 1)
            { TlsClientHelloSplit.TryFindSplit(payload, out _, out var reason, out var found); classification = reason; sni = found ?? sni; }
            if (outbound && !impostor && payload.Length > 0 && sni is null)
            {
                if (!_prefixes.TryGetValue(key, out var prefix) && payload[0] == 22)
                { prefix = new TlsPrefixAssembler(); _prefixes.Add(key, prefix); }
                if (prefix is not null)
                {
                    prefix.TryFindCurrentSplit(packet.Sequence, payload, Stopwatch.GetElapsedTime(_started), out _, out _);
                    sni = prefix.Sni ?? sni;
                }
            }
            _entries[key] = entry with
            {
                OutboundPackets = entry.OutboundPackets + (outbound ? 1 : 0),
                InboundPackets = entry.InboundPackets + (outbound ? 0 : 1),
                Syn = entry.Syn + ((packet.Flags & 0x12) == 2 ? 1 : 0),
                SynAck = entry.SynAck + ((packet.Flags & 0x12) == 0x12 ? 1 : 0),
                Reset = entry.Reset + ((packet.Flags & 4) != 0 ? 1 : 0),
                Fin = entry.Fin + ((packet.Flags & 1) != 0 ? 1 : 0),
                ClientHello = entry.ClientHello + (hello && payload[5] == 1 ? 1 : 0),
                ServerHello = entry.ServerHello + (hello && payload[5] == 2 ? 1 : 0),
                PlaintextAlert = entry.PlaintextAlert + (payload.Length >= 5 && payload[0] == 21 && payload[1] == 3 ? 1 : 0),
                EncryptedRecords = entry.EncryptedRecords + (payload.Length >= 5 && payload[0] == 23 && payload[1] == 3 ? 1 : 0),
                FirstOutboundUtc = outbound ? entry.FirstOutboundUtc ?? utc : entry.FirstOutboundUtc,
                LastOutboundUtc = outbound ? utc : entry.LastOutboundUtc,
                FirstInboundUtc = outbound ? entry.FirstInboundUtc : entry.FirstInboundUtc ?? utc,
                LastInboundUtc = outbound ? entry.LastInboundUtc : utc,
                InboundPayloadPackets = entry.InboundPayloadPackets + (!outbound && payload.Length > 0 ? 1 : 0),
                InboundPayloadBytes = entry.InboundPayloadBytes + (!outbound ? payload.Length : 0),
                FirstInboundPayloadUtc = !outbound && payload.Length > 0 ? entry.FirstInboundPayloadUtc ?? utc : entry.FirstInboundPayloadUtc,
                LastInboundPayloadUtc = !outbound && payload.Length > 0 ? utc : entry.LastInboundPayloadUtc,
                Sni = sni,
                EchExtensionObserved = ech,
                ServerHelloPrefixReassembled = server,
                TcpTimestampOptionObserved = timestampSample ? entry.TcpTimestampOptionObserved == true || timestamps : entry.TcpTimestampOptionObserved,
                TcpTimestampPeerEchoObserved = timestampSample ? entry.TcpTimestampPeerEchoObserved == true || timestamps && timestampEcho != 0 : entry.TcpTimestampPeerEchoObserved,
                InboundImpostorCopies = entry.InboundImpostorCopies + (!outbound && impostor ? 1 : 0),
                OutboundImpostorCopies = entry.OutboundImpostorCopies + (outbound && impostor ? 1 : 0),
                HandshakeProgress = progress,
                InboundReset = entry.InboundReset + (!outbound && (packet.Flags & 4) != 0 ? 1 : 0),
                OutboundReset = entry.OutboundReset + (outbound && (packet.Flags & 4) != 0 ? 1 : 0),
                InboundFin = entry.InboundFin + (!outbound && (packet.Flags & 1) != 0 ? 1 : 0),
                OutboundFin = entry.OutboundFin + (outbound && (packet.Flags & 1) != 0 ? 1 : 0),
                ClientHelloClassification = classification,
                OwnershipEvidence = owner.Evidence,
                ProcessId = owner.Identity.ProcessId,
                CreationUtc = DateTimeOffset.FromFileTime(owner.Identity.CreationTime),
                ComponentFileName = Path.GetFileName(owner.Identity.ImagePath),
                VersionDirectory = Path.GetFileName(Path.GetDirectoryName(owner.Identity.ImagePath))
            };
        }
    }
    internal void TlsFakeSent(TcpFlow flow, OwnedPacket owner)
    {
        lock (_gate)
        {
            var key = (flow, owner.Profile.Id, owner.Identity.CreationTime);
            var entry = Get(key, owner.Evidence);
            if (entry is not null) _entries[key] = entry with { TlsFakePackets = entry.TlsFakePackets + 1 };
        }
    }
    internal void SplitDecision(TcpFlow flow, OwnedPacket owner, string reason, bool success, int segments = 2,
        TcpOriginalDecision? decision = null)
    {
        lock (_gate)
        {
            var key = (flow, owner.Profile.Id, owner.Identity.CreationTime);
            var entry = Get(key, owner.Evidence); if (entry is null) return;
            if (segments is not (2 or 3)) throw new ArgumentOutOfRangeException(nameof(segments));
            var decisions = entry.DecisionCounts is null ? new Dictionary<string, long>() : entry.DecisionCounts.ToDictionary(pair => pair.Key, pair => pair.Value);
            if (decisions.ContainsKey(reason) || decisions.Count < 32) decisions[reason] = decisions.GetValueOrDefault(reason) + 1;
            _entries[key] = entry with
            {
                LastSplitDecision = reason,
                Sni = decision?.StructuralHostRange?.Sni ?? entry.Sni,
                SplitOriginals = entry.SplitOriginals + (success ? 1 : 0),
                SplitSegments = entry.SplitSegments + (success ? segments : 0),
                DecisionCounts = decisions,
                OriginalDecisionTrace = decision is null ? entry.OriginalDecisionTrace
                    : (entry.OriginalDecisionTrace ?? []).Count < 16 ? [.. entry.OriginalDecisionTrace ?? [], decision] : entry.OriginalDecisionTrace,
                DecisionTraceDropped = entry.DecisionTraceDropped + (decision is not null && (entry.OriginalDecisionTrace ?? []).Count >= 16 ? 1 : 0),
                ProcessId = owner.Identity.ProcessId,
                CreationUtc = DateTimeOffset.FromFileTime(owner.Identity.CreationTime),
                ComponentFileName = Path.GetFileName(owner.Identity.ImagePath),
                VersionDirectory = Path.GetFileName(Path.GetDirectoryName(owner.Identity.ImagePath))
            };
        }
    }
    // Works in baseline/reference too: read-only current TCP table, not native capture or historical ownership.
    public void SampleCurrentTables(IReadOnlyList<AppProfile> profiles, IReadOnlyList<AppProfile>? approvedProfiles = null)
    {
        var approved = approvedProfiles ?? new ApprovedApplicationComponents(profiles).Profiles;
        foreach (var v6 in new[] { false, true })
        {
            try
            {
                foreach (var row in TcpOwnership.ReadBindings(v6).Where(row => row.State is >= 2 and <= 12))
                {
                    var identity = ProcessOwnership.ReadIdentity(row.ProcessId);
                    if (identity is null || OwnershipPolicy.MatchImage(approved, identity) is not { } profile) continue;
                    lock (_gate)
                    {
                        var key = (row.Flow, profile.Id, identity.CreationTime);
                        var entry = Get(key, "current-tcp-table+image+birth; NOT capture authorization");
                        if (entry is not null) _entries[key] = entry with
                        {
                            LastTcpState = row.State,
                            ProcessId = identity.ProcessId,
                            CreationUtc = DateTimeOffset.FromFileTime(identity.CreationTime),
                            ComponentFileName = Path.GetFileName(identity.ImagePath),
                            VersionDirectory = Path.GetFileName(Path.GetDirectoryName(identity.ImagePath))
                        };
                    }
                }
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or IOException)
            { lock (_gate) _probeFailures++; }
        }
    }
    private TcpConnectionEvidence? Get((TcpFlow Flow, string Profile, long Birth) key, string evidence)
    {
        if (_entries.TryGetValue(key, out var entry)) return entry;
        if (_entries.Count >= 32) { _dropped++; return null; }
        entry = new("tcp-" + (_entries.Count + 1), key.Profile, key.Flow.Local.V6 ? "IPv6" : "IPv4", evidence,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, null, null, null, null, "NotObserved", 0, 0, "NotAttempted", null,
            RemotePort: key.Flow.RemotePort, RemoteAddressSha256: TcpFlowFingerprint.RemoteAddress(key.Flow), FlowSha256: TcpFlowFingerprint.Flow(key.Flow));
        _entries[key] = entry; return entry;
    }
    public TcpDiagnosticSnapshot Snapshot() { lock (_gate) return new(DateTimeOffset.UtcNow, _entries.Values.ToArray(), _unknown, _dropped, _probeFailures, _enabled, _drained, CaptureHealth: new Dictionary<string, long>(_health)); }
}
