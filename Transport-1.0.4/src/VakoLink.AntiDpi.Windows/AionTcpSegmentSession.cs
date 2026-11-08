using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public sealed record AionSegmentFlowEvidence(string FlowSha256, string RemoteAddressSha256, ushort RemotePort, uint ProcessId,
    string ComponentFileName, long OriginalsReplaced, long SegmentsSent, int MaximumSentPayload, long AfterCopies, int AfterMaximumPayload);
public sealed record AionSegmentEvidence(NativeEvidence Native, bool Running, string? Failure, string StrategyId, int PayloadLimit,
    ushort TargetPort, string TargetAddressSha256, long ReplacedOriginals, long SegmentsSent, long PassedOriginals, long SendFailures,
    long PartialFallbacks, long UnforwardedOriginals, bool NoFakePackets, bool StreamChecksPassed,
    IReadOnlyDictionary<string, long> Decisions, IReadOnlyList<AionSegmentFlowEvidence> Flows,
    string AfterScope = "All target outgoing copies after active handle; not physical wire proof");

public sealed class AionTcpSegmentSession : IAsyncDisposable
{
    private readonly SessionDependencies _deps;
    private readonly AppProfile _main;
    private readonly bool _smallBoundary;
    private string StrategyId => _smallBoundary ? AionSmallBoundarySplit.StrategyId : AionTcpSegmentation.StrategyId;
    private int PayloadLimit => _smallBoundary ? AionSmallBoundarySplit.MaximumSentPayload : AionTcpSegmentation.PayloadLimit;
    private readonly object _sync = new();
    private readonly SemaphoreSlim _stopGate = new(1, 1);
    private readonly Dictionary<(TcpFlow, uint, long, ulong), AionSegmentFlowEvidence> _flows = new();
    private readonly Dictionary<string, long> _decisions = new();
    private IDivertApi? _api;
    private IDisposable? _lease;
    private FileStream? _mainImageLock;
    private IReadOnlyList<IDisposable> _locks = [];
    private IntPtr _active, _after;
    private Task? _worker, _afterWorker;
    private CancellationTokenRegistration _cancel;
    private volatile bool _stopping, _running;
    private bool _loaded, _unloaded;
    private int _opened, _closed;
    private long _replaced, _segments, _passed, _sendFailures, _fallbacks, _unforwarded;
    private string? _failure;
    private ushort _port = AionTcpSegmentation.TargetPort;
    private string _target = AionTcpSegmentation.TargetAddressSha256;
    private bool _fixture;
    internal Func<TcpFlow, long, bool, OwnedPacket?>? TestResolver { get; init; }
    private OwnedPacket? Resolve(TcpFlow flow, long timestamp, bool mutation) => TestResolver is null ? Observer.ResolveTcp(flow, timestamp, mutation) : TestResolver(flow, timestamp, mutation);
    public GamePassiveTrace Observer { get; }
    public AionTcpSegmentSession(AppProfile main, IReadOnlyList<AppProfile> observe, bool smallBoundary = false) : this(main, observe, new SessionDependencies(), smallBoundary) { }
    internal AionTcpSegmentSession(AppProfile main, IReadOnlyList<AppProfile> observe, SessionDependencies deps, bool smallBoundary = false)
    {
        _main = main; _deps = deps; _smallBoundary = smallBoundary;
        Observer = new(observe, new SessionDependencies
        {
            IsAdministrator = deps.IsAdministrator,
            HasConflicts = deps.HasConflicts,
            VerifyPackage = deps.VerifyPackage,
            AcquireLease = () => new NoLease(),
            LockPackage = deps.LockPackage,
            LoadLibrary = deps.LoadLibrary
        }, detailedAion: smallBoundary);
    }
    public AionSegmentEvidence Evidence
    {
        get
        {
            lock (_sync)
            {
                var o = Observer.Evidence.Native;
                var native = new NativeEvidence(_opened + o.Opened, _closed + o.Closed, _loaded || o.DllLoaded,
                    (!_loaded || _unloaded) && (!o.DllLoaded || o.DllUnloaded), !_running && _active == IntPtr.Zero && _after == IntPtr.Zero && o.RollbackCompleted && _lease is null);
                return new(native, _running, _failure, StrategyId, PayloadLimit, _port, _target, Interlocked.Read(ref _replaced), Interlocked.Read(ref _segments), Interlocked.Read(ref _passed),
                    _sendFailures, _fallbacks, _unforwarded, true, true, new Dictionary<string, long>(_decisions), _flows.Values.ToArray(),
                    _smallBoundary ? "Only target outgoing payload1 or10 copies after active handle; may include existing1/10 originals; not physical wire proof" : "All target outgoing copies after active handle; not physical wire proof");
            }
        }
    }
    public Task StartOwnLoopbackSmokeAsync(string engine, ushort port, CancellationToken token)
    {
        if (_main.ExecutablePath != Environment.ProcessPath || port == 0) throw new InvalidOperationException("OWN_IMAGE_ONLY_FIXTURE");
        _fixture = true; _port = port;
        _target = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(new byte[] { 127, 0, 0, 1 }));
        return StartAsync(engine, token);
    }
    public async Task StartAsync(string engine, CancellationToken token)
    {
        if (_loaded || _running) throw new InvalidOperationException("AION_SEGMENT_ALREADY_STARTED");
        if (!_fixture && (Path.GetFileName(_main.ExecutablePath) != "AION2.exe" || _main.Id != "aion2"
            || ProfileBindingCollector.HashImage(_main).Sha256 != AionTcpSegmentation.ClientImageSha256 || !GameComponentTrust.IsSignedNcImage(_main.ExecutablePath)))
            throw new InvalidOperationException("AION_MAIN_IMAGE_NOT_PINNED");
        token.ThrowIfCancellationRequested();
        if (!_deps.IsAdministrator() || _deps.HasConflicts()) throw new InvalidOperationException("AION_SEGMENT_PREFLIGHT_CONFLICT");
        _deps.VerifyPackage(engine, token); _lease = _deps.AcquireLease();
        try
        {
            if (!_fixture)
            {
                _mainImageLock = new FileStream(_main.ExecutablePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (ProfileBindingCollector.HashImage(_main).Sha256 != AionTcpSegmentation.ClientImageSha256 || !GameComponentTrust.IsSignedNcImage(_main.ExecutablePath)) throw new InvalidOperationException("AION_LOCKED_IMAGE_CHANGED");
            }
            _locks = _deps.LockPackage(engine);
            if (_fixture && _smallBoundary) await Observer.StartDetailedLoopbackSmokeAsync(engine, _port, CancellationToken.None);
            else if (_fixture) await Observer.StartLoopbackSmokeAsync(engine, CancellationToken.None); else await Observer.StartAsync(engine, CancellationToken.None);
            _api = _deps.LoadLibrary(Path.Combine(engine, "WinDivert.dll")); _loaded = true;
            string scope = $"ip and tcp and tcp.DstPort == {_port} and {(_fixture ? "loopback" : "!loopback")}";
            _after = Open(scope + (_smallBoundary ? " and outbound and (tcp.PayloadLength == 1 or tcp.PayloadLength == 10)" : ""), 0, 5);
            _active = Open(scope + " and outbound and !impostor and tcp.PayloadLength " + (_smallBoundary ? "== 11" : "> 1000"), 50, 0);
            _running = true;
            _afterWorker = Worker(After); _worker = Worker(Capture);
            _cancel = token.Register(RequestStop);
            _ = Task.Run(async () => { while (_running && !_stopping) { await Task.Delay(200); if (!Observer.Evidence.Running || Observer.Evidence.Failure is not null) { Fail("AION_OBSERVER_FAILED"); break; } } });
        }
        catch { await StopAsync(); throw; }
    }
    private IntPtr Open(string filter, short priority, ulong flags)
    {
        var h = _api!.Open(filter, 0, priority, flags); if (h == IntPtr.Zero || h == new IntPtr(-1)) throw new InvalidOperationException("AION_SEGMENT_OPEN_FAILED");
        _opened++; return h;
    }
    private Task Worker(Action action) => Task.Factory.StartNew(() => { try { action(); } catch (Exception ex) { Fail("AION_WORKER_" + ex.GetType().Name); } }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    private void RequestStop() => _ = Task.Run(async () => { try { await StopAsync(); } catch { } });
    private void Fail(string code) { _failure ??= code; _stopping = true; RequestStop(); }
    private void Decision(string reason) { lock (_sync) _decisions[reason] = _decisions.GetValueOrDefault(reason) + 1; }
    internal void Handle(byte[] original, DivertAddress address)
    {
        bool complete = false;
        try
        {
            if (_stopping || !TcpPacket.TryParse(original, out var packet) || packet is null || packet.IsV6 || !address.Outbound || address.Impostor)
            { Decision("STOPPING_OR_PACKET_REFUSED"); return; }
            if (packet.Flow.RemotePort != _port || TcpFlowFingerprint.RemoteAddress(packet.Flow) != _target) { Decision("DESTINATION_NOT_TARGET"); return; }
            var owner = Resolve(packet.Flow, address.Timestamp, true);
            if (owner is null || owner.Profile.ExecutablePath != _main.ExecutablePath) { Decision("NO_MAIN_PROCESS_AUTHORIZATION"); return; }
            var key = (packet.Flow, owner.Identity.ProcessId, owner.Identity.CreationTime, owner.Endpoint);
            lock (_sync)
                if (_replaced >= AionTcpSegmentation.MaximumPerSession || _flows.TryGetValue(key, out var old) && old.OriginalsReplaced >= AionTcpSegmentation.MaximumPerFlow
                    || !_flows.ContainsKey(key) && _flows.Count >= AionTcpSegmentation.MaximumFlows) { Decision("SEGMENT_BUDGET_UNCHANGED"); return; }
            byte[][] pieces; string reason;
            bool built = _smallBoundary ? AionSmallBoundarySplit.TryBuild(original, out pieces, out reason) : AionTcpSegmentation.TryBuild(original, out pieces, out reason);
            if (!built) { Decision(reason); return; }
            var check = Resolve(packet.Flow, address.Timestamp, true);
            if (check is null || check.Endpoint != owner.Endpoint || !OwnershipPolicy.SameIdentity(check.Identity, owner.Identity)) { Decision("IDENTITY_CHANGED_BEFORE_SEND"); return; }
            lock (_sync)
                if (!_flows.ContainsKey(key)) _flows[key] = new(TcpFlowFingerprint.Flow(packet.Flow), _target, _port, owner.Identity.ProcessId, Path.GetFileName(owner.Identity.ImagePath), 0, 0, 0, 0, 0);
            int sent = 0;
            foreach (var piece in pieces)
            {
                var again = Resolve(packet.Flow, address.Timestamp, true);
                if (again is null || again.Endpoint != owner.Endpoint || !OwnershipPolicy.SameIdentity(again.Identity, owner.Identity) || _stopping)
                { if (sent > 0) { _fallbacks++; Fail("PARTIAL_IDENTITY_OR_STOP_FALLBACK"); } return; }
                var changed = address; changed.Bits |= (1u << 21) | (1u << 22);
                if (!Send(piece, ref changed)) { _fallbacks++; Fail("SEGMENT_SEND_FALLBACK"); return; }
                sent++;
                lock (_sync) { _segments++; var f = _flows[key]; _flows[key] = f with { SegmentsSent = f.SegmentsSent + 1, MaximumSentPayload = Math.Max(f.MaximumSentPayload, piece.Length - packet.PayloadOffset) }; }
            }
            complete = true;
            lock (_sync)
            {
                _replaced++;
                var f = _flows[key];
                _flows[key] = f with { OriginalsReplaced = f.OriginalsReplaced + 1 };
            }
            Decision(_smallBoundary ? "ORDERED_SMALL11_BOUNDARY_REPLACED" : "ORDERED_STREAM_REPLACED");
        }
        finally
        {
            if (!complete)
            {
                // A partially emitted prefix overlaps the original with IDENTICAL sequence/bytes. Never append new bytes.
                // The unmodified original fallback preserves TCP stream semantics; fail ends the experiment, not a retry.
                if (Send(original, ref address)) _passed++; else { _unforwarded++; Fail("ORIGINAL_FORWARD_UNCONFIRMED"); }
            }
        }
    }
    private bool Send(byte[] bytes, ref DivertAddress address)
    {
        try { if (_api!.Send(_active, bytes, (uint)bytes.Length, out var sent, ref address) && sent == bytes.Length) return true; }
        catch { }
        _sendFailures++; return false;
    }
    private void Capture()
    {
        var bytes = new byte[65535];
        while (_api!.Recv(_active, bytes, (uint)bytes.Length, out var size, out var address))
        {
            try { Handle(bytes.AsSpan(0, checked((int)size)).ToArray(), address); }
            catch (Exception ex) { Fail("AION_PACKET_" + ex.GetType().Name); } // Continue draining queued originals in pass-through mode.
        }
        if (!_stopping) throw new IOException("AION_ACTIVE_RECEIVE_FAILED");
    }
    private void After()
    {
        var bytes = new byte[65535];
        while (_api!.Recv(_after, bytes, (uint)bytes.Length, out var size, out var address))
        {
            if (!address.Outbound || !TcpPacket.TryParse(bytes.AsSpan(0, checked((int)size)), out var p) || p is null) continue;
            var o = Resolve(p.Flow, address.Timestamp, false); if (o is null) continue;
            var key = (p.Flow, o.Identity.ProcessId, o.Identity.CreationTime, o.Endpoint);
            lock (_sync) if (_flows.TryGetValue(key, out var f)) _flows[key] = f with { AfterCopies = f.AfterCopies + 1, AfterMaximumPayload = Math.Max(f.AfterMaximumPayload, p.PayloadLength) };
        }
        if (!_stopping) throw new IOException("AION_AFTER_RECEIVE_FAILED");
    }
    public async Task StopAsync()
    {
        await _stopGate.WaitAsync();
        try
        {
            _stopping = true; _cancel.Unregister();
            if (_api is not null)
            {
                if (_active != IntPtr.Zero) _api.Shutdown(_active, 1);
                if (_worker is not null) await _worker.WaitAsync(TimeSpan.FromSeconds(10));
                if (_after != IntPtr.Zero) _api.Shutdown(_after, 1);
                if (_afterWorker is not null) await _afterWorker.WaitAsync(TimeSpan.FromSeconds(10));
                Close(ref _active); Close(ref _after); _api.Dispose(); _api = null; _unloaded = true;
            }
            await Observer.StopAsync();
            foreach (var file in _locks) file.Dispose(); _locks = []; _mainImageLock?.Dispose(); _mainImageLock = null; _lease?.Dispose(); _lease = null; _running = false;
        }
        finally { _stopGate.Release(); }
    }
    private void Close(ref IntPtr handle)
    { if (handle == IntPtr.Zero) return; if (!_api!.Close(handle)) throw new InvalidOperationException("AION_CLOSE_UNCONFIRMED"); handle = IntPtr.Zero; _closed++; }
    public async ValueTask DisposeAsync() => await StopAsync();
    private sealed class NoLease : IDisposable { public void Dispose() { } }
}
