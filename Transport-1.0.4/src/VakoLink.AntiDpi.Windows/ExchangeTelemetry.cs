using System.Diagnostics;
using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public sealed record ExchangeActivity(string Direction, DateTimeOffset CapturedUtc, double ElapsedMilliseconds);

public sealed record ExchangeGap(string Direction, DateTimeOffset StartedUtc, DateTimeOffset? EndedUtc,
    double StartedElapsedMilliseconds, double? EndedElapsedMilliseconds, double DurationMilliseconds,
    bool WaitingForFirstInbound, bool EndedByStop, bool CorrelationWindowLimited);

public sealed record ExchangeStreamSnapshot(string Id, string? ProfileId, long OutboundCount, long InboundMatchedCount,
    DateTimeOffset? FirstOutboundUtc, DateTimeOffset? LastOutboundUtc, DateTimeOffset? FirstInboundUtc,
    DateTimeOffset? LastInboundUtc, double? FirstOutboundElapsedMilliseconds, double? LastOutboundElapsedMilliseconds,
    double? FirstInboundElapsedMilliseconds, double? LastInboundElapsedMilliseconds, bool CorrelationWindowActive,
    ExchangeGap? CurrentOutboundGap, ExchangeGap? CurrentInboundGap, IReadOnlyList<ExchangeGap> CompletedGaps,
    long GapsDropped, IReadOnlyList<ExchangeActivity> Activity, long ActivityDropped,
    IReadOnlyDictionary<string, long>? OutboundPayloadSizeBins = null, IReadOnlyDictionary<string, long>? InboundPayloadSizeBins = null);

public sealed record ExchangeTelemetrySnapshot(DateTimeOffset SnapshotUtc, double ElapsedMilliseconds,
    IReadOnlyList<ExchangeStreamSnapshot> Profiles, IReadOnlyList<ExchangeStreamSnapshot> Connections,
    long InboundObserved, long UnknownInbound, int CorrelationEntries, long CorrelationEntriesDropped,
    long ConnectionsDropped, long InvalidTimestamps, bool ObserverEnabled, bool DrainConfirmed, string TimeSource,
    string CorrelationNotes, string CollectionCompleteness);

public sealed record ExchangeObservationMark(string Id, DateTimeOffset CapturedUtc, long CaptureQpc,
    double ElapsedMilliseconds, ExchangeTelemetrySnapshot ExchangeAtClick, string CollectionCompleteness);

public sealed record LateExchangeCopies(string ProfileId, long OutboundCount, long InboundMatchedCount);

public sealed record UserEventExchangeTelemetry(ExchangeObservationMark Mark, ExchangeTelemetrySnapshot ExchangeAfterStop,
    IReadOnlyList<LateExchangeCopies> LateCopiesCapturedBeforeMark, bool DrainConfirmed, string CollectionCompleteness);

/// <summary>
/// Metadata-only correlation: a reverse tuple is not proof of peer identity, an acknowledgement or RTT.
/// There is no incoming Send call, packet/payload retention, endpoint or path in exported snapshots.
/// </summary>
internal sealed class ExchangeTelemetryCollector
{
    internal const int MaximumFlows = 4096;
    internal const int MaximumConnections = 32;
    // Reports may contain three snapshots. Small rings preserve bounded report size;
    // full counters/first/last survive eviction and drops are always exported.
    internal const int MaximumActivity = 8;
    internal const int MaximumGaps = 4;
    internal const int MaximumMarks = 2;
    internal const double QuietMilliseconds = 2000;
    internal const double CorrelationMilliseconds = 60_000;
    private readonly object _gate = new();
    private readonly long _frequency;
    private readonly Func<long> _clock;
    private readonly Func<DateTimeOffset> _utc;
    private readonly AppProfile[] _configured;
    private readonly Func<IReadOnlyList<AppProfile>>? _approvedProfiles;
    private readonly Dictionary<string, StreamState> _profiles;
    private readonly Dictionary<FlowKey, FlowEntry> _flows = new();
    private readonly List<StreamState> _connections = new();
    private readonly List<MarkState> _marks = new();
    private long _start;
    private DateTimeOffset _startedUtc;
    private long? _stopped;
    private long _nextSweep;
    private long _inbound;
    private long _unknown;
    private long _flowDrops;
    private long _connectionDrops;
    private long _invalid;
    private bool _drainConfirmed;
    private bool _started;
    private bool _observerEnabled;

    internal ExchangeTelemetryCollector(IReadOnlyList<AppProfile> profiles, long? frequency = null,
        Func<long>? clock = null, Func<DateTimeOffset>? utc = null, Func<IReadOnlyList<AppProfile>>? approvedProfiles = null)
    {
        _configured = profiles.ToArray();
        _approvedProfiles = approvedProfiles;
        _frequency = frequency ?? Stopwatch.Frequency;
        if (_frequency <= 0) throw new ArgumentOutOfRangeException(nameof(frequency));
        _clock = clock ?? Stopwatch.GetTimestamp;
        _utc = utc ?? (() => DateTimeOffset.UtcNow);
        _profiles = _configured.ToDictionary(p => p.Id, p => new StreamState(p.Id, null), StringComparer.OrdinalIgnoreCase);
    }

    internal void Start(bool observerEnabled = true)
    {
        lock (_gate)
        {
            if (_started) throw new InvalidOperationException("EXCHANGE_ALREADY_STARTED");
            _startedUtc = _utc(); _start = _clock(); _started = true; _observerEnabled = observerEnabled;
        }
    }

    internal static FlowKey Reverse(FlowKey flow) => new(flow.DestinationAddress, flow.DestinationPort,
        flow.SourceAddress, flow.SourcePort);

    internal bool RecordOutbound(FlowKey flow, OwnedPacket owned, long captured, int? payloadBytes = null)
    {
        lock (_gate)
        {
            if (_stopped is not null || !ValidTimestamp(captured)) { _invalid++; return false; }
            var matched = OwnershipPolicy.MatchImage(_approvedProfiles?.Invoke() ?? _configured, owned.Identity);
            if (owned.Endpoint == 0 || owned.Identity.ProcessId == 0 || owned.Identity.CreationTime <= 0
                || flow.SourcePort == 0 || flow.DestinationPort == 0
                || matched?.Id != owned.Profile.Id || !_profiles.TryGetValue(owned.Profile.Id, out var profile))
                return false;
            Sweep();
            if (_flows.TryGetValue(flow, out var entry)
                && (!OwnershipPolicy.SameIdentity(entry.Owned.Identity, owned.Identity) || entry.Owned.Endpoint != owned.Endpoint))
            { _flows.Remove(flow); entry = null; }
            if (entry is null)
            {
                if (_flows.Count >= MaximumFlows) _flowDrops++;
                else
                {
                    StreamState? connection = null;
                    if (_connections.Count < MaximumConnections)
                    {
                        connection = new StreamState("connection-" + (_connections.Count + 1), owned.Profile.Id);
                        _connections.Add(connection);
                    }
                    else _connectionDrops++;
                    entry = new FlowEntry(owned, captured, connection);
                    _flows.Add(flow, entry);
                }
            }
            if (entry is not null)
            {
                entry.FirstAuthorized = Math.Min(entry.FirstAuthorized, captured);
                entry.LastAuthorized = Math.Max(entry.LastAuthorized, captured);
                Record(entry.Connection, "Outbound", captured, payloadBytes);
            }
            Record(profile, "Outbound", captured, payloadBytes);
            RecordLate(owned.Profile.Id, "Outbound", captured);
            return true;
        }
    }

    internal bool ObserveInbound(FlowKey incoming, long captured, Func<FlowKey, long, OwnedPacket?> resolveCurrent, int? payloadBytes = null)
    {
        var outgoing = Reverse(incoming);
        FlowEntry? expected;
        lock (_gate)
        {
            _inbound++;
            if (_stopped is not null || !ValidTimestamp(captured)) { _invalid++; _unknown++; return false; }
            Sweep();
            if (!_flows.TryGetValue(outgoing, out expected) || captured < expected.FirstAuthorized
                || Milliseconds(_clock() - expected.LastAuthorized) > CorrelationMilliseconds)
            { _unknown++; return false; }
        }
        // Never hold the collector lock while querying Windows process/UDP ownership twice.
        var current = resolveCurrent(outgoing, captured);
        lock (_gate)
        {
            if (_stopped is not null || current is null || !_flows.TryGetValue(outgoing, out var actual)
                || !ReferenceEquals(expected, actual) || current.Profile.Id != expected.Owned.Profile.Id
                || current.Endpoint == 0 || current.Endpoint != expected.Owned.Endpoint
                || !OwnershipPolicy.SameIdentity(current.Identity, expected.Owned.Identity))
            { _unknown++; return false; }
            Record(_profiles[current.Profile.Id], "Inbound", captured, payloadBytes);
            Record(expected.Connection, "Inbound", captured, payloadBytes);
            RecordLate(current.Profile.Id, "Inbound", captured);
            return true;
        }
    }

    internal void RecordUnknownInbound()
    {
        lock (_gate) { _inbound++; _unknown++; }
    }

    internal ExchangeTelemetrySnapshot Snapshot()
    {
        lock (_gate) return SnapshotLocked();
    }

    internal ExchangeObservationMark CaptureUserEventObservation()
    {
        lock (_gate)
        {
            if (!_started || !_observerEnabled || _stopped is not null) throw new InvalidOperationException("EXCHANGE_MARK_REQUIRES_ACTIVE_SESSION");
            if (_marks.Count >= MaximumMarks) throw new InvalidOperationException("EXCHANGE_MARK_LIMIT");
            var captured = _clock();
            var mark = new ExchangeObservationMark("event-" + (_marks.Count + 1), _utc(), captured,
                Elapsed(captured), SnapshotLocked(captured),
                "Processed copies at click; pending earlier captured copies may arrive later. Error onset is unknown.");
            _marks.Add(new MarkState(mark, _configured.Select(p => p.Id)));
            return mark;
        }
    }

    internal UserEventExchangeTelemetry UserEventTelemetry(string id)
    {
        lock (_gate)
        {
            var mark = _marks.SingleOrDefault(m => m.Mark.Id == id) ?? throw new InvalidOperationException("EXCHANGE_MARK_UNKNOWN");
            return new(mark.Mark, SnapshotLocked(), Array.AsReadOnly(mark.Late.Select(pair =>
                new LateExchangeCopies(pair.Key, pair.Value.Outbound, pair.Value.Inbound)).ToArray()), _drainConfirmed,
                "Late pre-click copies counted separately. Final snapshot is after stop, not an exact click cutoff; "
                    + "pre-click gap snapshot is not reconciled with late copies. Error onset remains unknown.");
        }
    }

    internal void Stop(bool drainConfirmed)
    {
        lock (_gate)
        {
            if (_stopped is not null) return;
            var now = _clock();
            foreach (var state in _profiles.Values.Concat(_connections))
            {
                var snapshot = StreamSnapshot(state, now);
                foreach (var gap in new[] { snapshot.CurrentOutboundGap, snapshot.CurrentInboundGap })
                    if (gap is not null) AddGap(state, gap with { EndedUtc = Utc(now), EndedElapsedMilliseconds = Elapsed(now), EndedByStop = true });
            }
            _stopped = now; _drainConfirmed = drainConfirmed && _observerEnabled;
            _flows.Clear();
        }
    }

    private void Sweep()
    {
        var now = _clock();
        if (now < _nextSweep) return;
        foreach (var old in _flows.Where(pair => Milliseconds(now - pair.Value.LastAuthorized) > CorrelationMilliseconds).ToArray())
            _flows.Remove(old.Key);
        _nextSweep = now + _frequency;
    }

    private bool ValidTimestamp(long timestamp) => _started && _observerEnabled && timestamp >= _start && timestamp > 0
        && timestamp <= _clock() && Elapsed(timestamp) <= 1_200_000;
    private double Milliseconds(long ticks) => (double)ticks * 1000 / _frequency;
    private double Elapsed(long timestamp) => Math.Max(0, Milliseconds(timestamp - _start));
    private DateTimeOffset Utc(long timestamp) => _startedUtc.AddMilliseconds(Elapsed(timestamp));

    private void Record(StreamState? state, string direction, long captured, int? payloadBytes = null)
    {
        if (state is null) return;
        var inbound = direction == "Inbound";
        var previousOutbound = state.LastOutbound;
        if (inbound)
        {
            if (state.PendingInbound is not null && captured >= state.PendingInbound)
            {
                var expiry = (state.LastOutbound ?? state.PendingInbound.Value) + 60 * _frequency;
                var end = Math.Min(captured, expiry);
                if (Milliseconds(end - state.PendingInbound.Value) >= QuietMilliseconds)
                    AddGap(state, Gap("Inbound", state.PendingInbound.Value, end, state.LastInbound is null,
                        false, captured > expiry));
                state.PendingInbound = null;
            }
            state.Inbound++; state.FirstInbound = Math.Min(state.FirstInbound ?? captured, captured);
            state.LastInbound = Math.Max(state.LastInbound ?? captured, captured);
        }
        else
        {
            if (previousOutbound is not null && captured > previousOutbound
                && Milliseconds(captured - previousOutbound.Value) >= QuietMilliseconds)
                AddGap(state, Gap("Outbound", previousOutbound.Value, captured, false, false,
                    Milliseconds(captured - previousOutbound.Value) > CorrelationMilliseconds));
            if (captured > (state.LastInbound ?? long.MinValue))
            {
                if (state.PendingInbound is not null && previousOutbound is not null
                    && captured > previousOutbound && Milliseconds(captured - previousOutbound.Value) > CorrelationMilliseconds)
                {
                    var expiry = previousOutbound.Value + 60 * _frequency;
                    if (Milliseconds(expiry - state.PendingInbound.Value) >= QuietMilliseconds)
                        AddGap(state, Gap("Inbound", state.PendingInbound.Value, expiry, state.LastInbound is null, false, true));
                    state.PendingInbound = captured;
                }
                else state.PendingInbound = Math.Min(state.PendingInbound ?? captured, captured);
            }
            state.Outbound++; state.FirstOutbound = Math.Min(state.FirstOutbound ?? captured, captured);
            state.LastOutbound = Math.Max(state.LastOutbound ?? captured, captured);
        }
        if (payloadBytes is >= 0 and <= 65507)
        {
            var bin = payloadBytes <= 32 ? "0-32" : payloadBytes <= 128 ? "33-128" : payloadBytes <= 512 ? "129-512"
                : payloadBytes <= 1200 ? "513-1200" : "1201-65507";
            var bins = direction == "Inbound" ? state.InboundSizes : state.OutboundSizes;
            bins[bin] = bins.GetValueOrDefault(bin) + 1;
        }
        if (state.Activity.Count == MaximumActivity) { state.Activity.Dequeue(); state.ActivityDropped++; }
        state.Activity.Enqueue(new(direction, Utc(captured), Elapsed(captured)));
    }

    private void RecordLate(string profileId, string direction, long captured)
    {
        foreach (var mark in _marks)
        {
            if (captured > mark.Mark.CaptureQpc) continue;
            var previous = mark.Late[profileId];
            mark.Late[profileId] = direction == "Inbound" ? (previous.Outbound, previous.Inbound + 1) : (previous.Outbound + 1, previous.Inbound);
        }
    }

    private static void AddGap(StreamState state, ExchangeGap gap)
    {
        if (state.Gaps.Count == MaximumGaps) { state.Gaps.Dequeue(); state.GapsDropped++; }
        state.Gaps.Enqueue(gap);
    }

    private ExchangeGap Gap(string direction, long from, long? to, bool waiting, bool endedByStop, bool windowLimited,
        long? now = null) => new(direction, Utc(from), to is null ? null : Utc(to.Value), Elapsed(from),
            to is null ? null : Elapsed(to.Value), Milliseconds((to ?? now ?? _clock()) - from), waiting, endedByStop, windowLimited);

    private ExchangeStreamSnapshot StreamSnapshot(StreamState state, long now)
    {
        var active = _stopped is null && state.LastOutbound is not null
            && _flows.Values.Any(entry => (ReferenceEquals(entry.Connection, state)
                || state.ProfileId is null && entry.Owned.Profile.Id == state.Id)
                && Milliseconds(now - entry.LastAuthorized) <= CorrelationMilliseconds);
        ExchangeGap? Current(string direction, long? from, bool waiting) => active && from is not null
            && Milliseconds(now - from.Value) >= QuietMilliseconds ? Gap(direction, from.Value, null, waiting, false, false, now) : null;
        return new(state.Id, state.ProfileId, state.Outbound, state.Inbound,
            ConvertUtc(state.FirstOutbound), ConvertUtc(state.LastOutbound), ConvertUtc(state.FirstInbound), ConvertUtc(state.LastInbound),
            ConvertElapsed(state.FirstOutbound), ConvertElapsed(state.LastOutbound), ConvertElapsed(state.FirstInbound), ConvertElapsed(state.LastInbound),
            active, Current("Outbound", state.LastOutbound, false), Current("Inbound", state.PendingInbound, state.LastInbound is null),
            Array.AsReadOnly(state.Gaps.ToArray()), state.GapsDropped, Array.AsReadOnly(state.Activity.ToArray()), state.ActivityDropped,
            new Dictionary<string, long>(state.OutboundSizes), new Dictionary<string, long>(state.InboundSizes));
        DateTimeOffset? ConvertUtc(long? timestamp) => timestamp is null ? null : Utc(timestamp.Value);
        double? ConvertElapsed(long? timestamp) => timestamp is null ? null : Elapsed(timestamp.Value);
    }

    private ExchangeTelemetrySnapshot SnapshotLocked(long? captured = null)
    {
        var now = _stopped ?? captured ?? _clock();
        return new(_utc(), _started ? Elapsed(now) : 0,
            Array.AsReadOnly(_profiles.Values.Select(state => StreamSnapshot(state, now)).ToArray()),
            Array.AsReadOnly(_connections.Select(state => StreamSnapshot(state, now)).ToArray()),
            _inbound, _unknown, _flows.Count, _flowDrops, _connectionDrops, _invalid, _observerEnabled, _drainConfirmed,
            "Windows QPC / Stopwatch.Frequency; estimated UTC from single unbracketed session-start anchor",
            "Reverse exact IPv4 UDP tuple + preceding authorized outgoing capture + current same PID/image/creation/endpoint. "
                + "60s since last authorized outgoing; quiet threshold2s; opaque export32, flow cap4096. "
                + "Correlation is not peer authentication, acknowledgements, RTT, loss proof, game or voice success. "
                + "Unknown copies stay unattributed. No payload/endpoints retained in reports.",
            !_observerEnabled ? "NotMeasured: no passive inbound observer was started."
                : _stopped is null ? "Processed sniff copies; queued captures may lag. Baseline without observer is NotMeasured."
                : _drainConfirmed ? "Own observer workers drained; metadata collection ended. No application-delivery guarantee."
                    : "Partial metadata: observer drain not confirmed.");
    }

    private sealed class FlowEntry(OwnedPacket owned, long captured, StreamState? connection)
    {
        internal OwnedPacket Owned { get; } = owned;
        internal long FirstAuthorized { get; set; } = captured;
        internal long LastAuthorized { get; set; } = captured;
        internal StreamState? Connection { get; } = connection;
    }

    private sealed class StreamState(string id, string? profileId)
    {
        internal string Id { get; } = id;
        internal string? ProfileId { get; } = profileId;
        internal long Outbound, Inbound, GapsDropped, ActivityDropped;
        internal long? FirstOutbound, LastOutbound, FirstInbound, LastInbound, PendingInbound;
        internal Queue<ExchangeGap> Gaps { get; } = new();
        internal Queue<ExchangeActivity> Activity { get; } = new();
        internal Dictionary<string, long> OutboundSizes { get; } = new();
        internal Dictionary<string, long> InboundSizes { get; } = new();
    }

    private sealed class MarkState(ExchangeObservationMark mark, IEnumerable<string> profiles)
    {
        internal ExchangeObservationMark Mark { get; } = mark;
        internal Dictionary<string, (long Outbound, long Inbound)> Late { get; } = profiles.ToDictionary(p => p, _ => (0L, 0L));
    }
}
