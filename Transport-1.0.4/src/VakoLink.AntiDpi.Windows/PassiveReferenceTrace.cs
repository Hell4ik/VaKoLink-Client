using System.Diagnostics;
using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public sealed record PassiveReferenceEvidence(TcpDiagnosticSnapshot BeforeEngine, TcpDiagnosticSnapshot AfterEngine,
    NativeEvidence Native, IReadOnlyList<ReferenceFlowDecision> RuleProjection, long RuleProjectionDropped,
    bool PacketSendApiUsed = false, string Scope = "Own SNIFF|RECV_ONLY handles at +30000/-30000; original engine unchanged. After-engine copies include injected traffic, not application delivery proof.",
    PassiveWireEvidence? Wire = null);

public sealed class PassiveReferenceTrace : IAsyncDisposable
{
    private readonly SessionDependencies _dependencies;
    public PassiveReferenceTrace() : this(new SessionDependencies { AcquireLease = AcquirePassiveLease }) { }
    internal PassiveReferenceTrace(SessionDependencies dependencies) => _dependencies = dependencies;
    private static IDisposable AcquirePassiveLease()
    {
        var lease = new Mutex(false, "Local\\VakoLink.AntiDpi.PassiveReference", out var created);
        if (created) return lease;
        lease.Dispose(); throw new InvalidOperationException("OTHER_PASSIVE_TRACE_ACTIVE");
    }
    private IDivertApi? _api; private readonly List<IntPtr> _handles = []; private readonly List<Task> _workers = [];
    private readonly TcpDiagnosticCollector _before = new(), _after = new(); private TcpOwnership? _ownership;
    private readonly PassiveWireTrace _wire = new();
    private readonly object _gate = new(); private readonly Dictionary<string, ReferenceFlowDecision> _rules = new(); private long _dropped;
    private volatile bool _stopping; private int _opened, _closed; private bool _loaded, _unloaded; private string? _failure;
    private readonly SemaphoreSlim _stopGate = new(1, 1);
    private ReferenceConfiguration? _configuration; private IDisposable? _lease; private ApprovedApplicationComponents? _components;
    private CancellationTokenRegistration _cancel;
    private ushort? _localhostPort;
    private readonly List<IDisposable> _inputLocks = [];
    public PassiveReferenceEvidence Evidence
    {
        get
        {
            lock (_gate) return new(
        _before.Snapshot() with { OwnershipResolutionCalls = _ownership?.ResolutionCounts(), ComponentEvents = _ownership?.ComponentEvents() },
        _after.Snapshot(), new(_opened, _closed, _loaded, _unloaded, _handles.Count == 0 && (!_loaded || _unloaded)), _rules.Values.ToArray(), _dropped, Wire: _wire.Snapshot());
        }
    }
    public async Task StartAsync(string engine, IReadOnlyList<AppProfile> profiles, CancellationToken token, ReferenceConfiguration? configuration = null)
        => await StartCoreAsync(engine, profiles, token, configuration, null);
    public Task StartLoopbackSmokeAsync(string engine, ushort port, CancellationToken token)
    {
        if (port == 0) throw new ArgumentOutOfRangeException(nameof(port));
        var image = Environment.ProcessPath ?? throw new InvalidOperationException("OWN_IMAGE_REQUIRED");
        return StartCoreAsync(engine, [new("local-passive", "Own localhost diagnostic", image, "observe")], token, null, port);
    }
    private async Task StartCoreAsync(string engine, IReadOnlyList<AppProfile> profiles, CancellationToken token, ReferenceConfiguration? configuration, ushort? localhostPort)
    {
        _localhostPort = localhostPort;
        if (_loaded) throw new InvalidOperationException("PASSIVE_ALREADY_STARTED");
        if (!_dependencies.IsAdministrator()) throw new InvalidOperationException("ADMIN_REQUIRED");
        token.ThrowIfCancellationRequested();
        _dependencies.VerifyPackage(engine, token); _configuration = configuration ?? ReferenceConfiguration.Read(engine);
        _lease = _dependencies.AcquireLease();
        try
        {
            _inputLocks.AddRange(_dependencies.LockPackage(engine));
            _dependencies.VerifyPackage(engine, token);
            _components = new ApprovedApplicationComponents(profiles);
            _ownership = new TcpOwnership(profiles, (_, _) => { }, () => _components.Profiles);
            _api = _dependencies.LoadLibrary(Path.Combine(engine, "WinDivert.dll")); _loaded = true;
            _before.Start(true); _after.Start(true);
            var flow = Open("tcp", 2, 0); var socket = Open("tcp", 3, 0);
            var filter = localhostPort is { } port ? $"tcp and loopback and (tcp.SrcPort == {port} or tcp.DstPort == {port})" : "tcp and !loopback";
            var before = Open(filter, 0, 30000); var after = Open(filter, 0, -30000);
            _workers.Add(Worker(() => Events(flow))); _workers.Add(Worker(() => Events(socket)));
            _workers.Add(Worker(() => Copies(before, _before, true))); _workers.Add(Worker(() => Copies(after, _after, false)));
            _cancel = token.Register(() => _ = Task.Run(StopAsync));
            await Task.CompletedTask;
        }
        catch { await StopAsync(); throw; }
    }
    private IntPtr Open(string filter, int layer, short priority)
    {
        var handle = _api!.Open(filter, layer, priority, 5); // SNIFF=1 | RECV_ONLY=4, NEVER diversion.
        if (handle == IntPtr.Zero || handle == new IntPtr(-1)) throw new InvalidOperationException("PASSIVE_OPEN_FAILED");
        _handles.Add(handle); _opened++; return handle;
    }
    private Task Worker(Action action) => Task.Factory.StartNew(() => { try { action(); } catch (Exception e) { _failure ??= e.GetType().Name; } }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    private void Events(IntPtr handle)
    {
        while (_api!.Recv(handle, null, 0, out _, out var address)) _ownership!.Observe(address);
        if (!_stopping) _failure ??= "PASSIVE_EVENT_RECEIVE_FAILED";
    }
    private void Copies(IntPtr handle, TcpDiagnosticCollector collector, bool before)
    {
        var buffer = new byte[65535];
        while (_api!.Recv(handle, buffer, (uint)buffer.Length, out var size, out var address))
        {
            var bytes = buffer.AsSpan(0, checked((int)size)); bool parsed = TcpPacket.TryParse(bytes, out var packet) && packet is not null;
            collector.ObserveCapture(parsed, address.Outbound, address.Impostor); if (!parsed) continue;
            bool outbound = _localhostPort is { } port ? packet!.Flow.RemotePort == port : address.Outbound;
            var flow = outbound ? packet!.Flow : packet!.Flow.Reverse(); var owner = _ownership!.Resolve(flow, address.Timestamp, false);
            if (before && owner is not null && outbound && !address.Impostor && packet.PayloadLength > 0)
                collector.ObserveDivertedOriginal(packet, bytes[packet.PayloadOffset..], owner); // Diagnostic tracker only, despite method's historic name.
            collector.Copy(packet!, bytes, owner, outbound, address.Timestamp, address.Impostor);
            if (owner is not null) _wire.Observe(packet!, bytes, owner, outbound, before, address.Impostor, address.Timestamp, DateTimeOffset.UtcNow);
            if (before && owner is not null && outbound && !address.Impostor)
            {
                var hash = TcpFlowFingerprint.Flow(flow); var evidence = collector.Snapshot().Connections.FirstOrDefault(entry => entry.FlowSha256 == hash && entry.ProcessId == owner.Identity.ProcessId);
                var projection = _wire.Project(hash, _configuration!);
                if (projection is not null || evidence?.Sni is not null)
                    lock (_gate) { if (_rules.ContainsKey(hash) || _rules.Count < 32) _rules[hash] = projection ?? _configuration!.Evaluate(flow, evidence!.Sni); else _dropped++; }
            }
        }
        if (!_stopping) _failure ??= "PASSIVE_COPY_RECEIVE_FAILED";
    }
    public void Refresh() => _components?.Refresh();
    public async Task StopAsync()
    {
        await _stopGate.WaitAsync();
        try
        {
            _stopping = true;
            _cancel.Unregister();
            if (_api is not null)
            {
                foreach (var handle in _handles) _api.Shutdown(handle, 1);
                try { await Task.WhenAll(_workers).WaitAsync(TimeSpan.FromSeconds(10)); }
                catch (TimeoutException)
                {
                    _failure ??= "DRAIN_TIMEOUT";
                    CloseHandles();
                    // Never unload native code underneath a live receive worker.
                    await Task.WhenAll(_workers).WaitAsync(TimeSpan.FromSeconds(3));
                }
                CloseHandles();
                _api.Dispose(); _api = null; _unloaded = true;
            }
            _wire.Dispose();
            _before.Stop(_failure is null); _after.Stop(_failure is null); _lease?.Dispose(); _lease = null;
            foreach (var input in _inputLocks) input.Dispose(); _inputLocks.Clear();
            if (_failure is not null) throw new InvalidOperationException("PASSIVE_TRACE_FAILED_" + _failure);
        }
        finally { _stopGate.Release(); }
    }
    private void CloseHandles()
    {
        foreach (var handle in _handles.ToArray())
        {
            if (!_api!.Close(handle)) throw new InvalidOperationException("PASSIVE_CLOSE_UNCONFIRMED");
            _handles.Remove(handle); _closed++;
        }
    }
    public async ValueTask DisposeAsync() => await StopAsync();
}
