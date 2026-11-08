using System.Collections.Concurrent;
using System.Diagnostics;
using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public sealed record GamePacketMoment(DateTimeOffset Utc, bool Outbound, int PayloadBytes);
public sealed record GameConnectionEvidence(string Id, string Protocol, string AddressFamily, ushort RemotePort, string RemoteAddressSha256,
    uint ProcessId, string ComponentFileName, string ImageSha256, DateTimeOffset CreationUtc, string OwnershipEvidence,
    long OutboundPackets, long InboundPackets, long OutboundBytes, long InboundBytes,
    DateTimeOffset? FirstOutboundUtc, DateTimeOffset? LastOutboundUtc, DateTimeOffset? FirstInboundUtc, DateTimeOffset? LastInboundUtc,
    IReadOnlyList<GamePacketMoment> RecentActivity, long ActivityDropped, GameTcpProgress? Transport = null,
    IReadOnlyList<uint>? InterfaceIndexes = null, DateTimeOffset? FlowCloseObservedUtc = null, GameTcpWireMetrics? Wire = null, string? FlowSha256 = null, AionTcpDetail? Detail = null);
public sealed record GamePassiveEvidence(NativeEvidence Native, bool Running, string? Failure, long Captured, long Unsupported,
    long Unattributed, long ConnectionsDropped, IReadOnlyList<GameConnectionEvidence> Connections,
    IReadOnlyDictionary<string, long> OwnershipDecisions, bool PacketSendApiUsed = false,
    string Scope = "SNIFF|RECV_ONLY; TCP/UDP IPv4/IPv6 all ports, selected exact images only; payload never saved; UDP binding is selected FLOW identity, not mutation authorization",
    IReadOnlyDictionary<string, long>? DetailCounters = null, ClosedTcpTailEvidence? PostCloseTcpTail = null);

public sealed class GamePassiveTrace : IAsyncDisposable
{
    internal delegate bool ReferenceCopy(TcpPacket packet, ReadOnlySpan<byte> bytes, OwnedPacket owner, bool outbound, long qpc);
    internal delegate byte[]? ReferenceFragment(ReadOnlySpan<byte> bytes, bool outbound, uint iface, long qpc);
    internal delegate void ReferenceArrival(ReadOnlySpan<byte> bytes, DivertAddress address);
    private ReferenceArrival? _referenceArrival;
    private ReferenceFragment? _referenceFragment;
    private short _networkPriority = 100;
    private string? _referenceFilter;
    private ReferenceCopy? _referenceCopy;
    internal void ConfigureReferenceObservation(short priority, string filter, ReferenceCopy callback, ReferenceFragment? fragments = null, ReferenceArrival? arrival = null)
    {
        if (_loaded || priority is not (30000 or -30000)) throw new InvalidOperationException("REFERENCE_OBSERVER_CONFIGURATION_INVALID");
        _networkPriority = priority; _referenceFilter = filter; _referenceCopy = callback; _referenceFragment = fragments; _referenceArrival = arrival;
    }
    private readonly SessionDependencies _dependencies;
    private readonly IReadOnlyList<AppProfile> _profiles;
    private readonly Dictionary<string, string> _imageHashes;
    private readonly SemaphoreSlim _stopGate = new(1, 1);
    private readonly object _gate = new();
    private readonly ConcurrentDictionary<(byte, TcpFlow), FlowObservation> _udp = new();
    private readonly Dictionary<(byte, TcpFlow, uint, long, ulong), GameConnectionEvidence> _connections = new();
    private readonly Dictionary<(byte, TcpFlow, uint, long, ulong), GameTcpTracker> _transport = new();
    private readonly Dictionary<(byte, TcpFlow, uint, long, ulong), GameTcpWireObserver> _wire = new();
    private readonly Dictionary<(byte, TcpFlow, uint, long, ulong), AionTcpTimeline> _details = new();
    private readonly Dictionary<TcpFlow, (byte[] Header, long Timestamp, long Seen)> _pendingSyn = new();
    private readonly Dictionary<string, long> _detailCounters = new();
    private readonly bool _detailedAion;
    private readonly ClosedTcpObservationTail? _closeTail;
    private ushort _detailPort = AionTcpSegmentation.TargetPort;
    private string _detailTarget = AionTcpSegmentation.TargetAddressSha256;
    private readonly List<IntPtr> _handles = [];
    private readonly List<Task> _workers = [];
    private IReadOnlyList<IDisposable> _locks = [];
    private IDivertApi? _api; private IDisposable? _lease; private TcpOwnership? _tcpOwner;
    private readonly TcpDiagnosticCollector _tcp = new();
    private CancellationTokenRegistration _cancel;
    private volatile bool _stopping, _running;
    private int _opened, _closed; private bool _loaded, _unloaded; private string? _failure;
    private long _captured, _unsupported, _unattributed, _dropped;
    private bool _loopbackFixture;
    public GamePassiveTrace(IReadOnlyList<AppProfile> profiles, bool detailedAion = false, bool postCloseTail = false) : this(profiles, new SessionDependencies(), detailedAion, postCloseTail) { }
    internal GamePassiveTrace(IReadOnlyList<AppProfile> profiles, SessionDependencies dependencies, bool detailedAion = false, bool postCloseTail = false)
    {
        if (profiles.Count is < 1 or > 8 || profiles.Any(p => p.StrategyId != "observe")) throw new ArgumentException("GAME_PASSIVE_SCOPE_INVALID");
        _profiles = profiles.ToArray(); _dependencies = dependencies; _detailedAion = detailedAion;
        if (postCloseTail && !detailedAion) throw new ArgumentException("POST_CLOSE_REQUIRES_TARGET_DETAIL");
        _closeTail = postCloseTail ? new(Stopwatch.Frequency) : null;
        _imageHashes = profiles.ToDictionary(p => p.ExecutablePath, p => ProfileBindingCollector.HashImage(p).Sha256 ?? "UNKNOWN", StringComparer.OrdinalIgnoreCase);
    }
    public GamePassiveEvidence Evidence
    {
        get
        {
            lock (_gate) return new(new(_opened, _closed, _loaded, _unloaded, !_running && _handles.Count == 0 && (!_loaded || _unloaded)), _running,
                _failure, Interlocked.Read(ref _captured), Interlocked.Read(ref _unsupported), Interlocked.Read(ref _unattributed), _dropped,
                _connections.Values.ToArray(), _tcpOwner?.ResolutionCounts() ?? new Dictionary<string, long>(),
                Scope: _referenceFilter is not null ? "SNIFF RECV_ONLY exact reference address and TCP port; network filter not PID binding; saved copies attributed to selected exact images. First detailed target flow only; other flow summaries remain bounded. No Send API."
                    : "SNIFF|RECV_ONLY; TCP/UDP IPv4/IPv6 all ports, selected exact images only; payload never saved; UDP binding is selected FLOW identity, not mutation authorization",
                DetailCounters: _detailedAion ? new Dictionary<string, long>(_detailCounters) : null,
                PostCloseTcpTail: _closeTail?.Snapshot(Stopwatch.GetTimestamp()));
        }
    }
    public TcpDiagnosticSnapshot Tcp => _tcp.Snapshot() with { ComponentEvents = _tcpOwner?.ComponentEvents(), OwnershipResolutionCalls = _tcpOwner?.ResolutionCounts() };
    internal OwnedPacket? ResolveTcp(TcpFlow flow, long captured, bool mutation) => _tcpOwner?.Resolve(flow, captured, mutation);
    public Task StartDetailedLoopbackSmokeAsync(string engine, ushort port, CancellationToken token)
    {
        if (!_detailedAion || port == 0) throw new InvalidOperationException("DETAIL_FIXTURE_SCOPE_INVALID");
        _detailPort = port; _detailTarget = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(new byte[] { 127, 0, 0, 1 }));
        return StartLoopbackSmokeAsync(engine, token);
    }
    public Task StartLoopbackSmokeAsync(string engine, CancellationToken token)
    {
        if (_profiles.Any(p => p.ExecutablePath != Environment.ProcessPath)) throw new InvalidOperationException("OWN_LOOPBACK_IMAGE_REQUIRED");
        _loopbackFixture = true; return StartAsync(engine, token);
    }
    public async Task StartAsync(string engine, CancellationToken token)
    {
        if (_loaded) throw new InvalidOperationException("GAME_TRACE_ALREADY_STARTED");
        if (!_dependencies.IsAdministrator()) throw new InvalidOperationException("ADMIN_REQUIRED");
        if (_dependencies.HasConflicts()) throw new InvalidOperationException("CONFLICTING_ENGINE_ACTIVE");
        token.ThrowIfCancellationRequested(); _dependencies.VerifyPackage(engine, token);
        _lease = _dependencies.AcquireLease();
        try
        {
            _locks = _dependencies.LockPackage(engine); _dependencies.VerifyPackage(engine, token);
            _api = _dependencies.LoadLibrary(Path.Combine(engine, "WinDivert.dll")); _loaded = true;
            _tcpOwner = new(_profiles, (_, _) => { }); _tcp.Start(true);
            var flow = Open("tcp or udp", 2); var socket = Open("tcp or udp", 3);
            var network = Open(_referenceFilter ?? ((_detailedAion ? "((tcp or udp) or (ip and inbound and icmp))" : "(tcp or udp)") + (_loopbackFixture ? " and loopback" : " and !loopback")), 0);
            _running = true;
            _workers.Add(Worker(() => Events(flow))); _workers.Add(Worker(() => Events(socket))); _workers.Add(Worker(() => Copies(network)));
            _cancel = token.Register(() => _ = Task.Run(async () => { try { await StopAsync(); } catch { } }));
            await Task.CompletedTask;
        }
        catch { await StopAsync(); throw; }
    }
    private IntPtr Open(string filter, int layer)
    {
        var handle = _api!.Open(filter, layer, layer == 0 ? _networkPriority : (short)100, 5); // SNIFF=1|RECV_ONLY=4. NO Send anywhere in this class.
        if (handle == IntPtr.Zero || handle == new IntPtr(-1)) throw new InvalidOperationException("GAME_PASSIVE_OPEN_FAILED");
        _handles.Add(handle); _opened++; return handle;
    }
    private Task Worker(Action action) => Task.Factory.StartNew(() =>
    {
        try { action(); }
        catch (Exception ex) { _failure ??= "GAME_WORKER_" + ex.GetType().Name; _ = Task.Run(async () => { try { await StopAsync(); } catch { } }); }
    }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    private void Events(IntPtr handle)
    {
        while (_api!.Recv(handle, null, 0, out _, out var address))
        {
            if (_closeTail is not null && address.Protocol == 6 && address.Outbound && address.Endpoint != 0)
            {
                var eventFlow = TcpOwnership.EventFlow(address);
                if (IsDetailTarget(eventFlow))
                    _closeTail.ObserveEvent(eventFlow, address.ProcessId, ProcessOwnership.ReadIdentity(address.ProcessId)?.CreationTime,
                        address.Endpoint, address.Event, address.Timestamp, CaptureUtc(address.Timestamp), Stopwatch.GetTimestamp());
            }
            _tcpOwner!.Observe(address);
            if (address.Protocol == 6 && address.Event == 2)
            {
                var ended = TcpOwnership.EventFlow(address);
                lock (_gate)
                    foreach (var connectionKey in _connections.Keys.Where(k => k.Item1 == 6 && k.Item2 == ended && k.Item3 == address.ProcessId && k.Item5 == address.Endpoint).ToArray())
                        _connections[connectionKey] = _connections[connectionKey] with { FlowCloseObservedUtc = DateTimeOffset.UtcNow };
            }
            if (address.Protocol != 17 || !address.Outbound || address.Endpoint == 0) continue;
            if (address.Event is 2 or 7)
            { foreach (var pair in _udp.Where(p => p.Value.Endpoint == address.Endpoint)) ((ICollection<KeyValuePair<(byte, TcpFlow), FlowObservation>>)_udp).Remove(pair); continue; }
            if (address.Event is not (1 or 4)) continue;
            var identity = ProcessOwnership.ReadIdentity(address.ProcessId);
            if (identity is null || OwnershipPolicy.MatchImage(_profiles, identity) is null) continue;
            var key = (address.Protocol, TcpOwnership.EventFlow(address));
            if (_udp.Count < 256 || _udp.ContainsKey(key))
                _udp.AddOrUpdate(key, new FlowObservation(identity, address.Timestamp, Environment.TickCount64, address.Endpoint), (_, old) =>
                    OwnershipPolicy.SameIdentity(old.Identity, identity) && old.Endpoint == address.Endpoint ? old with { Timestamp = Math.Min(old.Timestamp, address.Timestamp) } : new(identity, address.Timestamp, Environment.TickCount64, address.Endpoint));
        }
        if (!_stopping) throw new IOException("GAME_EVENT_RECEIVE_FAILED");
    }
    private OwnedPacket? ResolveUdp(TcpFlow flow, long captured)
    {
        if (!_udp.TryGetValue((17, flow), out var history) || history.Timestamp > captured) return null;
        var identity = ProcessOwnership.ReadIdentity(history.Identity.ProcessId);
        if (identity is null || !OwnershipPolicy.SameIdentity(history.Identity, identity) || OwnershipPolicy.MatchImage(_profiles, identity) is not { } profile) return null;
        NativeMethods.GetSystemTimePreciseAsFileTime(out var fileTime);
        if (!NativeMethods.QueryPerformanceCounter(out var now) || !NativeMethods.QueryPerformanceFrequency(out var frequency)
            || !OwnershipPolicy.ProcessExistedAt(identity.CreationTime, fileTime, captured, now, frequency)) return null;
        return new(profile, identity, "selected-UDP-flow+exact-image+birth+capture-time; no UDP-table proof; read-only") { Endpoint = history.Endpoint };
    }
    private void Copies(IntPtr handle)
    {
        var buffer = new byte[65535];
        while (_api!.Recv(handle, buffer, (uint)buffer.Length, out var size, out var address))
        {
            Interlocked.Increment(ref _captured);
            var bytes = buffer.AsSpan(0, checked((int)size));
            _referenceArrival?.Invoke(bytes, address);
            byte[]? reassembled = null;
            try
            {
                if (_referenceFragment is not null && bytes.Length >= 20 && bytes[0] >> 4 == 4
                    && (System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(bytes[6..]) & 0x3FFF) != 0)
                {
                    reassembled = _referenceFragment(bytes, address.Outbound, address.InterfaceIndex, address.Timestamp);
                    if (reassembled is null) continue;
                    bytes = reassembled;
                }
                if (_detailedAion && !address.Outbound && bytes.Length >= 20 && bytes[0] >> 4 == 4 && bytes[9] == 1)
                { ObserveIcmp(bytes, address); continue; }
                if (!PassiveTransportPacket.TryParse(bytes, out var packet)) { Interlocked.Increment(ref _unsupported); continue; }
                var flow = address.Outbound ? packet!.Flow : packet!.Flow.Reverse();
                if (_detailedAion && address.Outbound && TcpPacket.TryParse(bytes, out var syn) && syn is { Flags: 2, PayloadLength: 0 } && IsDetailTarget(flow)) RememberSyn(syn, bytes, address);
                var owner = packet.Protocol == 6 ? _tcpOwner!.Resolve(flow, address.Timestamp, false) : ResolveUdp(flow, address.Timestamp);
                if (owner is null)
                {
                    if (_closeTail is not null && packet.Protocol == 6 && IsDetailTarget(flow) && TcpPacket.TryParse(bytes, out var historic) && historic is not null)
                        _closeTail.ObserveUnowned(historic, bytes, address.Outbound, address.Timestamp, CaptureUtc(address.Timestamp), Stopwatch.GetTimestamp());
                    // Do NOT return historical ownership to ResolveTcp, collectors or mutation authorization.
                    Interlocked.Increment(ref _unattributed); continue;
                }
                TcpPacket? tcp = null;
                bool synthetic = false;
                if (packet.Protocol == 6)
                {
                    bool parsed = TcpPacket.TryParse(bytes, out tcp);
                    _tcp.ObserveCapture(parsed, address.Outbound, address.Impostor);
                }
                if (tcp is not null)
                {
                    if (_closeTail is not null && IsDetailTarget(flow) && (_loopbackFixture || owner.Profile.Id == "aion2"
                        && Path.GetFileName(owner.Identity.ImagePath) == "AION2.exe" && _imageHashes[owner.Profile.ExecutablePath] == AionTcpSegmentation.ClientImageSha256))
                        _closeTail.ObserveSelected(tcp, bytes, owner, address.Outbound, address.Timestamp, CaptureUtc(address.Timestamp), Stopwatch.GetTimestamp());
                    synthetic = _referenceCopy?.Invoke(tcp, bytes, owner, address.Outbound, address.Timestamp) == true;
                    if (address.Outbound && !address.Impostor && !synthetic && tcp.PayloadLength > 0) _tcp.ObserveDivertedOriginal(tcp, bytes[tcp.PayloadOffset..], owner);
                    _tcp.Copy(tcp, bytes, owner, address.Outbound, address.Timestamp, address.Impostor);
                }
                var utc = DateTimeOffset.UtcNow - TimeSpan.FromSeconds(Math.Clamp((Stopwatch.GetTimestamp() - address.Timestamp) / (double)Stopwatch.Frequency, 0, 1200));
                lock (_gate)
                {
                    var key = (packet.Protocol, flow, owner.Identity.ProcessId, owner.Identity.CreationTime, owner.Endpoint);
                    if (!_connections.TryGetValue(key, out var c))
                    {
                        int limit = _detailedAion ? packet.Protocol == 6 && IsDetailTarget(flow) ? 32 : 30 : 128;
                        if (_connections.Count >= limit) { _dropped++; continue; } // Reserve two summary slots for target; bounded duplicated failure snapshots stay below recorder budget.
                        c = new("game-" + (_connections.Count + 1), packet.Protocol == 6 ? "TCP" : "UDP", flow.Local.V6 ? "IPv6" : "IPv4", flow.RemotePort,
                            TcpFlowFingerprint.RemoteAddress(flow), owner.Identity.ProcessId, Path.GetFileName(owner.Identity.ImagePath), _imageHashes[owner.Profile.ExecutablePath],
                            DateTimeOffset.FromFileTime(owner.Identity.CreationTime).ToUniversalTime(), owner.Evidence,
                            0, 0, 0, 0, null, null, null, null, [], 0, FlowSha256: packet.Protocol == 6 ? TcpFlowFingerprint.Flow(flow) : null);
                    }
                    var activity = c.RecentActivity.Append(new GamePacketMoment(utc, address.Outbound, packet.PayloadBytes)).TakeLast(64).ToArray();
                    GameTcpProgress? progress = c.Transport;
                    var wire = c.Wire;
                    if (tcp is not null)
                    {
                        if (!_transport.TryGetValue(key, out var tracker)) { tracker = new(requireSyn: _referenceFilter is not null); _transport.Add(key, tracker); }
                        tracker.Observe(tcp.Sequence, tcp.Acknowledgment, tcp.Flags, bytes[tcp.PayloadOffset..], address.Outbound, utc, synthetic);
                        progress = tracker.Snapshot();
                        if (!_wire.TryGetValue(key, out var observer)) { observer = new(); _wire.Add(key, observer); }
                        observer.Observe(tcp, bytes, address.Outbound); wire = observer.Snapshot();
                        if (_detailedAion && IsDetailTarget(flow))
                        {
                            if (_loopbackFixture || owner.Profile.Id == "aion2" && Path.GetFileName(owner.Identity.ImagePath) == "AION2.exe" && _imageHashes[owner.Profile.ExecutablePath] == AionTcpSegmentation.ClientImageSha256)
                            {
                                if (!_details.TryGetValue(key, out var detail) && _details.Count < (_referenceFilter is null ? AionTcpTimeline.FlowLimit : 1)) { detail = new(requireSyn: _referenceFilter is not null); _details[key] = detail; }
                                if (detail is not null)
                                {
                                    if (!address.Outbound && tcp.Flags == 18) CorrelateSyn(detail, flow, tcp, owner);
                                    detail.Observe(tcp, bytes, address.Outbound, utc, synthetic: synthetic);
                                    c = c with { Detail = detail.Snapshot() };
                                }
                                else DetailCount("DETAIL_CONNECTION_LIMIT");
                            }
                            else DetailCount("TARGET_COMPONENT_NOT_PINNED");
                        }
                    }
                    _connections[key] = c with
                    {
                        OutboundPackets = c.OutboundPackets + (address.Outbound ? 1 : 0),
                        InboundPackets = c.InboundPackets + (address.Outbound ? 0 : 1),
                        OutboundBytes = c.OutboundBytes + (address.Outbound ? packet.PayloadBytes : 0),
                        InboundBytes = c.InboundBytes + (address.Outbound ? 0 : packet.PayloadBytes),
                        FirstOutboundUtc = address.Outbound ? c.FirstOutboundUtc ?? utc : c.FirstOutboundUtc,
                        LastOutboundUtc = address.Outbound ? utc : c.LastOutboundUtc,
                        FirstInboundUtc = address.Outbound ? c.FirstInboundUtc : c.FirstInboundUtc ?? utc,
                        LastInboundUtc = address.Outbound ? c.LastInboundUtc : utc,
                        RecentActivity = activity,
                        ActivityDropped = c.ActivityDropped + (c.RecentActivity.Count >= 64 ? 1 : 0),
                        Transport = progress,
                        Wire = wire,
                        InterfaceIndexes = (c.InterfaceIndexes ?? []).Append(address.InterfaceIndex).Distinct().Take(8).ToArray()
                    };
                }
            }
            finally { if (reassembled is not null) System.Security.Cryptography.CryptographicOperations.ZeroMemory(reassembled); }
        }
        if (!_stopping) throw new IOException("GAME_COPY_RECEIVE_FAILED");
    }
    private bool IsDetailTarget(TcpFlow flow) => !flow.Local.V6 && flow.RemotePort == _detailPort && TcpFlowFingerprint.RemoteAddress(flow) == _detailTarget;
    private static DateTimeOffset CaptureUtc(long qpc) => DateTimeOffset.UtcNow - TimeSpan.FromSeconds(Math.Clamp((Stopwatch.GetTimestamp() - qpc) / (double)Stopwatch.Frequency, 0, 1200));
    private void DetailCount(string code) { lock (_gate) _detailCounters[code] = _detailCounters.GetValueOrDefault(code) + 1; }
    private void RememberSyn(TcpPacket syn, ReadOnlySpan<byte> bytes, DivertAddress address)
    {
        lock (_gate)
        {
            foreach (var key in _pendingSyn.Where(p => Environment.TickCount64 - p.Value.Seen > 3000).Select(p => p.Key).ToArray())
            { System.Security.Cryptography.CryptographicOperations.ZeroMemory(_pendingSyn[key].Header); _pendingSyn.Remove(key); DetailCount("SYN_CANDIDATE_EXPIRED"); }
            if (_pendingSyn.Count >= 16 && !_pendingSyn.ContainsKey(syn.Flow)) { DetailCount("SYN_CANDIDATE_LIMIT"); return; }
            if (_pendingSyn.Remove(syn.Flow, out var prior)) System.Security.Cryptography.CryptographicOperations.ZeroMemory(prior.Header);
            _pendingSyn[syn.Flow] = (bytes.ToArray(), address.Timestamp, Environment.TickCount64);
            DetailCount("SYN_HEADER_CANDIDATE_RETAINED"); // PayloadLength==0; never authorizes a process or mutation.
        }
    }
    private void CorrelateSyn(AionTcpTimeline detail, TcpFlow flow, TcpPacket synAck, OwnedPacket owner)
    {
        if (!_pendingSyn.Remove(flow, out var pending)) return;
        try
        {
            if (detail.Snapshot().LocalSynObserved) { DetailCount("SYN_ALREADY_SELECTED_CAPTURE"); return; }
            NativeMethods.GetSystemTimePreciseAsFileTime(out var fileTime);
            if (Environment.TickCount64 - pending.Seen > 3000 || !AionTcpTimeline.MatchingSynCandidate(pending.Header, synAck)
                || !TcpPacket.TryParse(pending.Header, out var syn) || syn is null || !NativeMethods.QueryPerformanceCounter(out var now)
                || !NativeMethods.QueryPerformanceFrequency(out var frequency)
                || !OwnershipPolicy.ProcessExistedAt(owner.Identity.CreationTime, fileTime, pending.Timestamp, now, frequency))
            { DetailCount("SYN_CANDIDATE_CORRELATION_REFUSED"); return; }
            var utc = DateTimeOffset.UtcNow - TimeSpan.FromSeconds(Math.Clamp((Stopwatch.GetTimestamp() - pending.Timestamp) / (double)Stopwatch.Frequency, 0, 3));
            detail.Observe(syn, pending.Header, true, utc, "CorrelatedPreauthorizationSyn"); DetailCount("SYN_HEADER_CORRELATED_READ_ONLY");
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(pending.Header); }
    }
    private void ObserveIcmp(ReadOnlySpan<byte> bytes, DivertAddress address)
    {
        if (!QuotedTcpError.TryParse(bytes, out var error) || error is null || !IsDetailTarget(error.Flow)) { DetailCount("ICMP_NOT_SELECTED_TARGET_QUOTE"); return; }
        var owner = _tcpOwner!.Resolve(error.Flow, address.Timestamp, false);
        if (owner is null) { DetailCount("TARGET_ICMP_CURRENT_OWNERSHIP_UNCONFIRMED"); return; }
        var key = ((byte)6, error.Flow, owner.Identity.ProcessId, owner.Identity.CreationTime, owner.Endpoint);
        lock (_gate)
        {
            if (!_details.TryGetValue(key, out var detail)) { DetailCount("TARGET_ICMP_NO_SELECTED_DETAIL"); return; }
            var utc = DateTimeOffset.UtcNow - TimeSpan.FromSeconds(Math.Clamp((Stopwatch.GetTimestamp() - address.Timestamp) / (double)Stopwatch.Frequency, 0, 1200));
            detail.ObserveIcmp(error.Type, error.Code, error.NextHopMtu, error.Sequence, utc);
            if (_connections.TryGetValue(key, out var c)) _connections[key] = c with { Detail = detail.Snapshot() };
            DetailCount("SELECTED_TARGET_ICMP_ERROR");
        }
    }
    public async Task StopAsync()
    {
        await _stopGate.WaitAsync();
        try
        {
            _stopping = true; _cancel.Unregister();
            if (_api is not null)
            {
                foreach (var handle in _handles) _api.Shutdown(handle, 1);
                try { await Task.WhenAll(_workers).WaitAsync(TimeSpan.FromSeconds(10)); }
                catch (TimeoutException)
                {
                    _failure ??= "GAME_DRAIN_TIMEOUT"; CloseHandles();
                    try { await Task.WhenAll(_workers).WaitAsync(TimeSpan.FromSeconds(3)); }
                    catch { throw new InvalidOperationException("GAME_WORKER_RETAINED_DLL_NOT_UNLOADED"); }
                }
                CloseHandles(); _api.Dispose(); _api = null; _unloaded = true;
            }
            foreach (var input in _locks) input.Dispose(); _locks = []; _lease?.Dispose(); _lease = null;
            _tcp.Stop(_failure is null); _running = false;
            _closeTail?.Dispose();
            lock (_gate)
            {
                foreach (var tracker in _transport.Values) tracker.Dispose(); _transport.Clear(); _wire.Clear();
                foreach (var detail in _details.Values) detail.Dispose(); _details.Clear();
                foreach (var syn in _pendingSyn.Values) System.Security.Cryptography.CryptographicOperations.ZeroMemory(syn.Header); _pendingSyn.Clear();
            }
            if (_failure is not null) throw new InvalidOperationException("GAME_TRACE_FAILED");
        }
        finally { _stopGate.Release(); }
    }
    private void CloseHandles()
    {
        foreach (var handle in _handles.ToArray())
        {
            if (!_api!.Close(handle)) throw new InvalidOperationException("GAME_CLOSE_UNCONFIRMED");
            _handles.Remove(handle); _closed++;
        }
    }
    public async ValueTask DisposeAsync() => await StopAsync();
}
