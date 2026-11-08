using System.Diagnostics;
using System.Security.Cryptography;
using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public sealed record AionSynFlowEvidence(string FlowSha256, uint ProcessId, DateTimeOffset BirthUtc, string ImageSha256,
    long Attempts, long Changes, long ByteMatchedAfterSyn, long PeerSynAckWithTimestamp, long PeerSynAckWithoutTimestamp,
    long OutboundPayloadWithTimestamp, long OutboundPayloadWithoutTimestamp, long InboundPayloadWithTimestamp,
    long InboundPayloadWithoutTimestamp, DateTimeOffset FirstAttemptUtc, bool TimestampOffObserved, DateTimeOffset? FirstConfirmedSendUtc = null);
public sealed record AionSynDecision(DateTimeOffset Utc, string FlowSha256, string Code, double? ProofWaitMilliseconds = null);
public sealed record AionSynEvidence(NativeEvidence Native, bool Running, string? Failure, string StrategyId, string TargetAddressSha256,
    ushort Port, long Attempts, long Changes, long PassedOriginals, long SendFailures, long UnforwardedOriginals,
    IReadOnlyList<AionSynFlowEvidence> Flows, IReadOnlyDictionary<string, long> Decisions, IReadOnlyList<AionSynDecision> RecentDecisions,
    DateTimeOffset? ActiveOpenedUtc, int ProofWaitMilliseconds = 100, bool PayloadMutated = false, bool FakePackets = false,
    bool HistoricalMutationAuthorization = false, string Scope = "Own backend: exact pinned IPv4 destination/TCP13328, locked signed main image, fresh CONNECT/FLOW + two current tables + PID/birth/endpoint; only initial plain SYN TS offer to NOP, valid checksums. No data/control/UDP/IPv6 modification. Byte-matched after capture is not physical wire/application proof; raw header proof expires at 5s/128 entries.");

public sealed class AionSynTimestampSession : IAsyncDisposable
{
    private readonly AppProfile _main; private readonly SessionDependencies _deps;
    private readonly object _gate = new(); private readonly SemaphoreSlim _stopGate = new(1, 1);
    private readonly Dictionary<(TcpFlow, uint, long, ulong), AionSynFlowEvidence> _flows = new();
    private readonly Dictionary<(TcpFlow, uint, long, ulong), uint> _synOrigins = new();
    private AionSynFlowEvidence[]? _finalFlows;
    private readonly Dictionary<(TcpFlow, uint, long, ulong, uint), (byte[] Header, long Seen)> _pending = new();
    private readonly Dictionary<string, long> _decisions = new(); private readonly Queue<AionSynDecision> _recent = new();
    private IDivertApi? _api; private IDisposable? _lease; private FileStream? _imageLock; private IReadOnlyList<IDisposable> _locks = [];
    private IntPtr _active, _after; private Task? _worker, _afterWorker, _supervisor; private CancellationTokenRegistration _cancel;
    private volatile bool _stopping, _running; private bool _loaded, _unloaded, _fixture;
    private int _opened, _closed, _handling; private long _attempts, _changes, _passed, _sendFailures, _unforwarded;
    private DateTimeOffset? _openedUtc; private string? _failure; private string _target = AionTcpSegmentation.TargetAddressSha256;
    internal Func<TcpFlow, long, bool, OwnedPacket?>? TestResolver { get; init; }
    internal Func<TcpFlow, bool>? TestMainHint { get; init; }
    public GamePassiveTrace Observer { get; }
    public AionSynTimestampSession(AppProfile main, IReadOnlyList<AppProfile> observe) : this(main, observe, new SessionDependencies()) { }
    internal AionSynTimestampSession(AppProfile main, IReadOnlyList<AppProfile> observe, SessionDependencies deps)
    {
        _main = main; _deps = deps;
        Observer = new(observe, new SessionDependencies
        {
            IsAdministrator = deps.IsAdministrator,
            HasConflicts = deps.HasConflicts,
            VerifyPackage = deps.VerifyPackage,
            AcquireLease = () => new NoLease(),
            LockPackage = deps.LockPackage,
            LoadLibrary = deps.LoadLibrary
        }, detailedAion: true, postCloseTail: true);
    }
    public AionSynEvidence Evidence
    {
        get
        {
            lock (_gate)
            {
                var n = Observer.Evidence.Native;
                return new(new(_opened + n.Opened, _closed + n.Closed, _loaded || n.DllLoaded, (!_loaded || _unloaded) && (!n.DllLoaded || n.DllUnloaded),
                    !_running && _active == IntPtr.Zero && _after == IntPtr.Zero && n.RollbackCompleted && _lease is null), _running, _failure,
                    AionSynTimestamp.StrategyId, _target, 13328, _attempts, _changes, _passed, _sendFailures, _unforwarded,
                    (_finalFlows ?? _flows.Values.ToArray()).Select(f => f with
                    {
                        TimestampOffObserved = f.Changes > 0 && f.ByteMatchedAfterSyn > 0 && f.PeerSynAckWithoutTimestamp > 0
                        && f.PeerSynAckWithTimestamp == 0 && f.OutboundPayloadWithoutTimestamp > 0 && f.OutboundPayloadWithTimestamp == 0 && f.InboundPayloadWithTimestamp == 0 && _sendFailures == 0
                    }).ToArray(),
                    new Dictionary<string, long>(_decisions), _recent.ToArray(), _openedUtc);
            }
        }
    }
    private OwnedPacket? Resolve(TcpFlow f, long qpc, bool mutation) => TestResolver is null ? Observer.ResolveTcp(f, qpc, mutation) : TestResolver(f, qpc, mutation);
    private bool MainHint(TcpFlow f)
    {
        if (TestMainHint is not null) return TestMainHint(f);
        try { var pid = TcpOwnership.UniqueOwner(TcpOwnership.ReadBindings(false), f); return pid is uint id && ProcessOwnership.ReadIdentity(id) is { } i && string.Equals(i.ImagePath, _main.ExecutablePath, StringComparison.OrdinalIgnoreCase); }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or System.ComponentModel.Win32Exception) { return false; }
    }
    public Task StartOwnFixtureAsync(string engine, CancellationToken token)
    {
        if (_main.ExecutablePath != Environment.ProcessPath) throw new InvalidOperationException("OWN_IMAGE_FIXTURE_ONLY");
        _fixture = true; _target = Convert.ToHexString(SHA256.HashData(new byte[] { 127, 0, 0, 1 }));
        return StartAsync(engine, "127.0.0.1", token);
    }
    public async Task StartAsync(string engine, string privateAddress, CancellationToken token)
    {
        if (_loaded || _running) throw new InvalidOperationException("SYN_BACKEND_ALREADY_STARTED");
        if (!System.Net.IPAddress.TryParse(privateAddress, out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
            || Convert.ToHexString(SHA256.HashData(ip.GetAddressBytes())) != _target) throw new InvalidOperationException("SYN_TARGET_NOT_PINNED");
        if (!_fixture && (_main.Id != "aion2" || Path.GetFileName(_main.ExecutablePath) != "AION2.exe" || ProfileBindingCollector.HashImage(_main).Sha256 != AionTcpSegmentation.ClientImageSha256
            || !GameComponentTrust.IsSignedNcImage(_main.ExecutablePath))) throw new InvalidOperationException("SYN_MAIN_NOT_PINNED");
        token.ThrowIfCancellationRequested();
        if (!_deps.IsAdministrator() || _deps.HasConflicts()) throw new InvalidOperationException("SYN_PREFLIGHT_CONFLICT");
        _deps.VerifyPackage(engine, token); _lease = _deps.AcquireLease();
        try
        {
            if (!_fixture)
            {
                _imageLock = new(_main.ExecutablePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (ProfileBindingCollector.HashImage(_main).Sha256 != AionTcpSegmentation.ClientImageSha256 || !GameComponentTrust.IsSignedNcImage(_main.ExecutablePath)) throw new InvalidOperationException("SYN_LOCKED_IMAGE_CHANGED");
            }
            _locks = _deps.LockPackage(engine);
            if (_fixture) await Observer.StartDetailedLoopbackSmokeAsync(engine, 13328, CancellationToken.None); else await Observer.StartAsync(engine, CancellationToken.None);
            _api = _deps.LoadLibrary(Path.Combine(engine, "WinDivert.dll")); _loaded = true;
            var filters = AionSynFilterVerification.Filters(privateAddress, _fixture);
            _after = Open(filters.After, 0, 5);
            _active = Open(filters.Active, 50, 0);
            _openedUtc = DateTimeOffset.UtcNow; _running = true;
            _afterWorker = Worker(After); _worker = Worker(Capture); _cancel = token.Register(RequestStop);
            _supervisor = Task.Run(async () => { while (_running && !_stopping) { await Task.Delay(200); lock (_gate) PruneProofs(); if (!Observer.Evidence.Running || Observer.Evidence.Failure is not null) { Fail("SYN_OBSERVER_FAILED"); break; } } });
        }
        catch { await StopAsync(); throw; }
    }
    private IntPtr Open(string filter, short priority, ulong flags)
    { var h = _api!.Open(filter, 0, priority, flags); if (h == IntPtr.Zero || h == new IntPtr(-1)) throw new InvalidOperationException("SYN_OPEN_FAILED"); _opened++; return h; }
    private Task Worker(Action action) => Task.Factory.StartNew(() => { try { action(); } catch (Exception ex) { Fail("SYN_WORKER_" + ex.GetType().Name); } }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    private void RequestStop() => _ = Task.Run(async () => { try { await StopAsync(); } catch { } });
    private void Fail(string code) { _failure ??= code; _stopping = true; RequestStop(); }
    private void Decision(TcpFlow f, string code, double? waitMs = null)
    { lock (_gate) { _decisions[code] = _decisions.GetValueOrDefault(code) + 1; if (_recent.Count == 32) _recent.Dequeue(); _recent.Enqueue(new(DateTimeOffset.UtcNow, TcpFlowFingerprint.Flow(f), code, waitMs)); } }
    internal void Handle(byte[] original, DivertAddress address)
    {
        Interlocked.Increment(ref _handling);
        bool sentChanged = false;
        try
        {
            if (_stopping || !address.Outbound || address.Impostor || !TcpPacket.TryParse(original, out var p) || p is null || p.IsV6) return;
            if (p.Flow.RemotePort != 13328 || TcpFlowFingerprint.RemoteAddress(p.Flow) != _target) { Decision(p.Flow, "DESTINATION_NOT_TARGET"); return; }
            if (!AionSynTimestamp.TryBuild(original, out var changed, out var reason)) { Decision(p.Flow, reason); return; }
            var o = Resolve(p.Flow, address.Timestamp, true);
            if (o is null && MainHint(p.Flow))
            {
                var wait = Stopwatch.StartNew();
                while (o is null && !_stopping && wait.ElapsedMilliseconds < AionSynTimestamp.ProofWaitMilliseconds) { Thread.Sleep(5); o = Resolve(p.Flow, address.Timestamp, true); }
                Decision(p.Flow, "CURRENT_EVENT_PROOF_WAIT", wait.Elapsed.TotalMilliseconds);
            }
            if (o is null || o.Endpoint == 0 || !string.Equals(o.Profile.ExecutablePath, _main.ExecutablePath, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(o.Identity.ImagePath, _main.ExecutablePath, StringComparison.OrdinalIgnoreCase)) { Decision(p.Flow, "CURRENT_MAIN_AUTHORIZATION_NOT_PROVEN"); return; }
            var key = (p.Flow, o.Identity.ProcessId, o.Identity.CreationTime, o.Endpoint);
            lock (_gate)
            {
                PruneProofs();
                if (_synOrigins.TryGetValue(key, out var origin) && origin != p.Sequence) { Decision(p.Flow, "SYN_TUPLE_REUSE_NOT_CONTINUED"); return; }
                if (_attempts >= AionSynTimestamp.MaximumSynPerSession || _flows.TryGetValue(key, out var old) && old.Attempts >= AionSynTimestamp.MaximumSynPerFlow
                    || !_flows.ContainsKey(key) && _flows.Count >= AionSynTimestamp.MaximumFlows) { Decision(p.Flow, "SYN_BUDGET_UNCHANGED"); return; }
            }
            var again = Resolve(p.Flow, address.Timestamp, true);
            if (again is null || again.Endpoint != o.Endpoint || !OwnershipPolicy.SameIdentity(o.Identity, again.Identity) || _stopping) { Decision(p.Flow, "SYN_IDENTITY_CHANGED_BEFORE_SEND"); return; }
            lock (_gate)
            {
                if (!_flows.ContainsKey(key)) _flows[key] = new(TcpFlowFingerprint.Flow(p.Flow), o.Identity.ProcessId, DateTimeOffset.FromFileTime(o.Identity.CreationTime).ToUniversalTime(),
                    _fixture ? new('A', 64) : AionTcpSegmentation.ClientImageSha256, 0, 0, 0, 0, 0, 0, 0, 0, 0, DateTimeOffset.UtcNow, false);
                var proofKey = (p.Flow, o.Identity.ProcessId, o.Identity.CreationTime, o.Endpoint, p.Sequence);
                _synOrigins[key] = p.Sequence;
                if (_pending.Remove(proofKey, out var previous)) CryptographicOperations.ZeroMemory(previous.Header);
                _pending[proofKey] = (original.ToArray(), Environment.TickCount64); _attempts++; _flows[key] = _flows[key] with { Attempts = _flows[key].Attempts + 1 };
            }
            var a = address; a.Bits |= (1u << 21) | (1u << 22);
            sentChanged = Send(changed, ref a);
            if (sentChanged) { lock (_gate) { _changes++; _flows[key] = _flows[key] with { Changes = _flows[key].Changes + 1, FirstConfirmedSendUtc = _flows[key].FirstConfirmedSendUtc ?? DateTimeOffset.UtcNow }; } Decision(p.Flow, "SYN_TS_OFFER_REMOVED"); }
            else Fail("SYN_CHANGED_SEND_UNCONFIRMED");
        }
        finally
        {
            try { if (!sentChanged) { if (Send(original, ref address)) Interlocked.Increment(ref _passed); else { _unforwarded++; Fail("SYN_ORIGINAL_FORWARD_UNCONFIRMED"); } } }
            finally { Interlocked.Decrement(ref _handling); }
        }
    }
    private bool Send(byte[] b, ref DivertAddress a)
    { try { if (_api!.Send(_active, b, (uint)b.Length, out var sent, ref a) && sent == b.Length) return true; } catch { } Interlocked.Increment(ref _sendFailures); return false; }
    private void Capture()
    {
        var buffer = new byte[65535];
        while (_api!.Recv(_active, buffer, (uint)buffer.Length, out var size, out var address))
            try { Handle(buffer.AsSpan(0, checked((int)size)).ToArray(), address); } catch (Exception ex) { Fail("SYN_PACKET_" + ex.GetType().Name); }
        if (!_stopping) throw new IOException("SYN_ACTIVE_RECEIVE_FAILED");
    }
    internal void ObserveAfter(ReadOnlySpan<byte> b, DivertAddress address)
    {
        if (!TcpPacket.TryParse(b, out var p) || p is null) return;
        var f = address.Outbound ? p.Flow : p.Flow.Reverse(); if (f.RemotePort != 13328 || TcpFlowFingerprint.RemoteAddress(f) != _target) return;
        var o = Resolve(f, address.Timestamp, false); if (o is null) return;
        var key = (f, o.Identity.ProcessId, o.Identity.CreationTime, o.Endpoint);
        lock (_gate)
        {
            PruneProofs(); if (!_flows.TryGetValue(key, out var e)) return;
            var ts = AionSynTimestamp.TimestampPresent(b); if (ts is null) { Decision(f, "AFTER_OPTIONS_UNKNOWN"); return; }
            if (address.Outbound && p.Flags == 2)
            {
                var proofKey = (f, o.Identity.ProcessId, o.Identity.CreationTime, o.Endpoint, p.Sequence);
                if (_pending.TryGetValue(proofKey, out var original) && AionSynTimestamp.MatchesCapture(original.Header, b))
                { _pending.Remove(proofKey); CryptographicOperations.ZeroMemory(original.Header); e = e with { ByteMatchedAfterSyn = e.ByteMatchedAfterSyn + 1 }; }
                else Decision(f, "AFTER_SYN_MATCH_NOT_PROVEN");
            }
            else if (!address.Outbound && (p.Flags & 18) == 18) e = ts == true ? e with { PeerSynAckWithTimestamp = e.PeerSynAckWithTimestamp + 1 } : e with { PeerSynAckWithoutTimestamp = e.PeerSynAckWithoutTimestamp + 1 };
            else if (p.PayloadLength > 0)
            {
                if (address.Outbound) e = ts == true ? e with { OutboundPayloadWithTimestamp = e.OutboundPayloadWithTimestamp + 1 } : e with { OutboundPayloadWithoutTimestamp = e.OutboundPayloadWithoutTimestamp + 1 };
                else e = ts == true ? e with { InboundPayloadWithTimestamp = e.InboundPayloadWithTimestamp + 1 } : e with { InboundPayloadWithoutTimestamp = e.InboundPayloadWithoutTimestamp + 1 };
            }
            _flows[key] = e;
        }
    }
    private void After()
    { var b = new byte[65535]; while (_api!.Recv(_after, b, (uint)b.Length, out var size, out var a)) ObserveAfter(b.AsSpan(0, checked((int)size)), a); if (!_stopping) throw new IOException("SYN_AFTER_RECEIVE_FAILED"); }
    private void PruneProofs()
    { foreach (var key in _pending.Where(p => Environment.TickCount64 - p.Value.Seen > 5000).Select(p => p.Key).ToArray()) { CryptographicOperations.ZeroMemory(_pending[key].Header); _pending.Remove(key); } }
    public async Task StopAsync()
    {
        await _stopGate.WaitAsync();
        try
        {
            _stopping = true; _cancel.Unregister();
            if (_api is not null)
            {
                if (_active != IntPtr.Zero) _api.Shutdown(_active, 1); if (_worker is not null) await _worker.WaitAsync(TimeSpan.FromSeconds(10));
                var drain = Stopwatch.StartNew();
                while (Volatile.Read(ref _handling) > 0) { if (drain.ElapsedMilliseconds > 10000) throw new InvalidOperationException("SYN_HANDLER_RETAINED_DLL"); await Task.Delay(5); }
                if (_after != IntPtr.Zero) _api.Shutdown(_after, 1); if (_afterWorker is not null) await _afterWorker.WaitAsync(TimeSpan.FromSeconds(10));
                if (_supervisor is not null) await _supervisor.WaitAsync(TimeSpan.FromSeconds(2));
                Close(ref _active); Close(ref _after); _api.Dispose(); _api = null; _unloaded = true;
            }
            await Observer.StopAsync();
            lock (_gate) { foreach (var p in _pending.Values) CryptographicOperations.ZeroMemory(p.Header); _pending.Clear(); _finalFlows ??= _flows.Values.ToArray(); _flows.Clear(); _synOrigins.Clear(); }
            foreach (var l in _locks) l.Dispose(); _locks = []; _imageLock?.Dispose(); _imageLock = null; _lease?.Dispose(); _lease = null; _running = false;
        }
        finally { _stopGate.Release(); }
    }
    private void Close(ref IntPtr h) { if (h == IntPtr.Zero) return; if (!_api!.Close(h)) throw new InvalidOperationException("SYN_CLOSE_UNCONFIRMED"); h = IntPtr.Zero; _closed++; }
    public async ValueTask DisposeAsync() => await StopAsync();
    private sealed class NoLease : IDisposable { public void Dispose() { } }
}
