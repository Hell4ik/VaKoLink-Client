using System.Diagnostics;

namespace VakoLink.AntiDpi.Windows;

public sealed record LatencyStatistics(
    long Samples,
    long InvalidSamples,
    double MaximumMilliseconds,
    double P50Milliseconds,
    double P95Milliseconds,
    bool Approximate,
    string TimeSource,
    string Measurement);

public sealed record SessionTelemetrySnapshot(
    long NetworkCaptured,
    long Authorized,
    long Unattributed,
    long NotSelected,
    long Unknown,
    long ObserveOriginals,
    long ReinjectedOriginals,
    long SyntheticPackets,
    long SendFailures,
    double ElapsedMilliseconds,
    LatencyStatistics CaptureToRelease,
    LatencyStatistics ProcessingTime,
    IReadOnlyList<ProfileBindingEvidence> ProfileBindings,
    long BindingIdentitiesDropped,
    SessionTelemetrySnapshot? Tcp = null,
    string CounterScope = "IPv4 UDP originals, UDP fakes and UDP timings only; TCP is separate");

internal enum PacketAttribution
{
    Unknown,
    NotSelected,
    Authorized,
}

/// <summary>Fixed histogram storage; quantiles are bucket upper bounds, never retained packet samples.</summary>
internal sealed class BoundedLatencyHistogram
{
    internal const double MaximumSampleMilliseconds = 1_200_000;
    private static readonly double[] Bounds =
    [
        .005, .01, .02, .05, .1, .2, .5, 1, 2, 5, 10, 20, 50, 100, 200, 500,
        1000, 2000, 5000, 10000, 20000, 60000, 120000, 300000, 600000, MaximumSampleMilliseconds,
    ];
    private readonly long[] _counts = new long[Bounds.Length];
    private long _samples;
    private long _invalid;
    private double _maximum;

    internal int StorageBuckets => _counts.Length;

    internal void Record(double milliseconds)
    {
        if (!double.IsFinite(milliseconds) || milliseconds < 0 || milliseconds > MaximumSampleMilliseconds)
        {
            _invalid++;
            return;
        }
        _samples++;
        _maximum = Math.Max(_maximum, milliseconds);
        for (var index = 0; index < Bounds.Length; index++)
        {
            if (milliseconds <= Bounds[index])
            {
                _counts[index]++;
                return;
            }
        }
    }

    internal LatencyStatistics Snapshot(string measurement) => new(_samples, _invalid, _maximum,
        Percentile(.50), Percentile(.95), true, "Windows QPC / Stopwatch.Frequency", measurement);

    private double Percentile(double percentile)
    {
        if (_samples == 0) return 0;
        var rank = (long)Math.Ceiling(_samples * percentile);
        long cumulative = 0;
        for (var index = 0; index < Bounds.Length; index++)
        {
            cumulative += _counts[index];
            if (cumulative >= rank) return Bounds[index];
        }
        return Bounds[^1];
    }
}

internal sealed class SessionTelemetryAccumulator
{
    private readonly object _gate = new();
    private readonly long _frequency;
    private readonly Func<long> _clock;
    private readonly BoundedLatencyHistogram _capture = new();
    private readonly BoundedLatencyHistogram _processing = new();
    private long _started;
    private long? _stopped;
    private bool _observeOnly;
    private bool _hasStarted;
    private long _captured;
    private long _authorized;
    private long _notSelected;
    private long _unknown;
    private long _observed;
    private long _reinjected;
    private long _synthetic;
    private long _failed;

    internal SessionTelemetryAccumulator(long? frequency = null, Func<long>? clock = null)
    {
        _frequency = frequency ?? Stopwatch.Frequency;
        if (_frequency <= 0) throw new ArgumentOutOfRangeException(nameof(frequency));
        _clock = clock ?? Stopwatch.GetTimestamp;
    }

    internal void Start(bool observeOnly)
    {
        lock (_gate)
        {
            if (_hasStarted) throw new InvalidOperationException("TELEMETRY_ALREADY_STARTED");
            _started = _clock();
            _hasStarted = true;
            _observeOnly = observeOnly;
        }
    }

    internal void Capture()
    {
        lock (_gate) _captured++;
    }

    internal void SendCompleted(bool synthetic, bool success)
    {
        lock (_gate)
        {
            if (!success) _failed++;
            else if (synthetic) _synthetic++;
            else _reinjected++;
        }
    }

    internal void PacketCompleted(PacketAttribution attribution, bool sniff, long capturedAt,
        long processingStarted, long completedAt)
    {
        lock (_gate)
        {
            if (attribution == PacketAttribution.Authorized) _authorized++;
            else if (attribution == PacketAttribution.NotSelected) _notSelected++;
            else _unknown++;
            if (sniff) _observed++;
            _capture.Record(ToMilliseconds(capturedAt, completedAt));
            _processing.Record(ToMilliseconds(processingStarted, completedAt));
        }
    }

    private double ToMilliseconds(long from, long to) => from <= 0 || to < from
        ? double.NaN : ((double)to - from) * 1000 / _frequency;

    internal void Stop()
    {
        lock (_gate) _stopped ??= _clock();
    }

    internal SessionTelemetrySnapshot Snapshot(IReadOnlyList<ProfileBindingEvidence> bindings, long dropped)
    {
        lock (_gate)
        {
            var elapsed = _hasStarted ? Math.Max(0, ((double)(_stopped ?? _clock()) - _started) * 1000 / _frequency) : 0;
            return new(_captured, _authorized, _notSelected + _unknown, _notSelected, _unknown,
                _observed, _reinjected, _synthetic, _failed, elapsed,
                _capture.Snapshot(_observeOnly
                    ? "Capture-to-observation-completion; original already passed by sniff, not network-release latency"
                    : "Capture-to-WinDivertSend-return (includes driver queue and userspace processing)"),
                _processing.Snapshot("WinDivertRecv-return to packet processing/reinjection completion; excludes capture queue"),
                bindings, dropped);
        }
    }
}
