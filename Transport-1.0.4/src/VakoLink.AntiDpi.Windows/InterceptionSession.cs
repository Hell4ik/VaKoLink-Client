using System.Runtime.InteropServices;
using System.Diagnostics;
using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public record ProfileSnapshot(string ProfileId, string State, long ObservedPackets, long FakePackets, long TcpSplitPackets = 0, long TlsFakePackets = 0);
public record SessionSnapshot(bool Running, string State, IReadOnlyList<ProfileSnapshot> Profiles, long PassedThrough, long SendFailures);
public record NativeEvidence(int Opened, int Closed, bool DllLoaded, bool DllUnloaded, bool RollbackCompleted);

internal sealed class SessionDependencies
{
    internal Func<bool> IsAdministrator { get; init; } = RuntimePreflight.IsAdministrator;
    internal Action<string, CancellationToken> VerifyPackage { get; init; } = RuntimePreflight.VerifyPackage;
    internal Func<bool> HasConflicts { get; init; } = () => RuntimePreflight.GetConflicts().Count != 0;
    internal Func<IDisposable> AcquireLease { get; init; } = AcquireProductionLease;
    internal Func<string, IReadOnlyList<IDisposable>> LockPackage { get; init; } = LockProductionPackage;
    internal Func<string, IDivertApi> LoadLibrary { get; init; } = path => new NativeDivertApi(path);
    internal Func<TimeSpan, CancellationToken, Task> DelayAsync { get; init; } = Task.Delay;

    private static IDisposable AcquireProductionLease()
    {
        // Existence lease: unlike mutex ownership, it crosses async continuation threads safely.
        var lease = new Mutex(false, "Local\\VakoLink.AntiDpi.Interception", out var created);
        if (created) return lease;
        lease.Dispose();
        throw new InvalidOperationException("OTHER_ANTIDPI_SESSION_ACTIVE");
    }

    private static IReadOnlyList<IDisposable> LockProductionPackage(string directory)
    {
        var locks = new List<IDisposable>();
        try
        {
            locks.Add(new FileStream(Path.Combine(directory, "WinDivert.dll"), FileMode.Open, FileAccess.Read, FileShare.Read));
            locks.Add(new FileStream(Path.Combine(directory, "WinDivert64.sys"), FileMode.Open, FileAccess.Read, FileShare.Read));
            return locks;
        }
        catch
        {
            foreach (var acquired in locks) acquired.Dispose();
            throw;
        }
    }
}

public sealed class InterceptionSession : IAsyncDisposable
{
    private readonly Action<string> _safeLog;
    private readonly SessionDependencies _dependencies;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _snapshotLock = new();
    private readonly List<IntPtr> _handles = new();
    private readonly List<Task> _workers = new();
    private readonly Dictionary<string, ProfileSnapshot> _profiles = new();
    private IDivertApi? _library;
    private ProcessOwnership? _ownership;
    private TcpOwnership? _tcpOwnership;
    private TcpDiagnosticCollector _tcp = new();
    private readonly Dictionary<(TcpFlow, ulong), int> _tcpBudget = new();
    private readonly Dictionary<(TcpFlow, ulong, long), (TlsPrefixAssembler Prefix, long Started)> _tlsPrefixes = new();
    private readonly Dictionary<(TcpFlow, ulong, long), (TlsHostRangeAssembler Prefix, long Started)> _hostRanges = new();
    private FlowBudget _budget = new();
    private SessionTelemetryAccumulator _telemetry = new();
    private SessionTelemetryAccumulator _tcpTelemetry = new();
    private ExchangeTelemetryCollector _exchange = new(Array.Empty<AppProfile>());
    private ProfileBindingCollector _bindings = new(Array.Empty<AppProfile>());
    private ApprovedApplicationComponents? _components;
    private CancellationTokenSource? _deadline;
    private CancellationTokenRegistration _callerCancellation;
    private IDisposable? _singleInstance;
    private volatile bool _stopping;
    private volatile bool _running;
    private string _state = "Stopped";
    private long _passed;
    private long _failed;
    private int _opened;
    private int _closed;
    private bool _loaded;
    private bool _unloaded;
    private string? _failure;
    private readonly List<IDisposable> _packageLocks = new();

    public InterceptionSession(Action<string> safeLog) : this(safeLog, new SessionDependencies()) { }

    internal InterceptionSession(Action<string> safeLog, SessionDependencies dependencies)
    {
        _safeLog = safeLog ?? throw new ArgumentNullException(nameof(safeLog));
        _dependencies = dependencies ?? throw new ArgumentNullException(nameof(dependencies));
    }

    public Task StartAsync(IReadOnlyList<AppProfile> profiles, string engineDirectory, TimeSpan duration,
        CancellationToken cancellationToken = default) => StartInternalAsync(profiles, engineDirectory, duration, false, cancellationToken);

    // Native resource/ABI smoke: filter=false, never captures or injects a packet.
    public Task StartNativeSmokeAsync(string engineDirectory, CancellationToken cancellationToken = default) =>
        StartInternalAsync(Array.Empty<AppProfile>(), engineDirectory, TimeSpan.FromSeconds(2), true, cancellationToken);

    public Task StartLoopbackSmokeAsync(string engineDirectory, ushort receiverPort, CancellationToken cancellationToken = default)
    {
        if (receiverPort == 0) throw new ArgumentOutOfRangeException(nameof(receiverPort));
        var image = Environment.ProcessPath ?? throw new InvalidOperationException("PROCESS_IMAGE_UNAVAILABLE");
        return StartInternalAsync([new AppProfile("local-smoke", "Local smoke", image, "udp-fake-ttl2")],
            engineDirectory, TimeSpan.FromSeconds(8), false, cancellationToken, receiverPort);
    }

    // Diagnostic-only loopback impact probe. Normal production filters and lifetime policy are unchanged.
    public Task StartImpactSmokeAsync(string engineDirectory, ushort receiverPort, bool observeOnly,
        CancellationToken cancellationToken = default)
    {
        if (receiverPort == 0) throw new ArgumentOutOfRangeException(nameof(receiverPort));
        var image = Environment.ProcessPath ?? throw new InvalidOperationException("PROCESS_IMAGE_UNAVAILABLE");
        return StartInternalAsync([new AppProfile("local-smoke", "Local impact smoke", image,
            observeOnly ? "observe" : "udp-fake-ttl2")], engineDirectory, TimeSpan.FromSeconds(15), false,
            cancellationToken, receiverPort);
    }

    public Task StartTcpLoopbackSmokeAsync(string directory, ushort port, CancellationToken token = default, bool observeOnly = false, bool disorder = false, bool tlsFake = false, bool hostFake = false, bool structuralHostFake = false)
    {
        if (port == 0) throw new ArgumentOutOfRangeException(nameof(port));
        var image = Environment.ProcessPath ?? throw new InvalidOperationException("PROCESS_IMAGE_UNAVAILABLE");
        return StartInternalAsync([new("tls-local", "TLS local", image, observeOnly ? "observe" : structuralHostFake ? "discord-hostfake-range-ts" : hostFake ? "discord-hostfake-ts" : tlsFake ? "discord-tls-fake-seq-split" : disorder ? "discord-tls-disorder" : "discord-tls-split")], directory,
            TimeSpan.FromSeconds(15), false, token, tcpSmokePort: port);
    }

    private async Task StartInternalAsync(IReadOnlyList<AppProfile> profiles, string directory, TimeSpan duration,
        bool nativeSmoke, CancellationToken token, ushort? loopbackSmokePort = null, ushort? tcpSmokePort = null)
    {
        await _gate.WaitAsync(token);
        if (_library is not null)
        {
            _gate.Release();
            throw new InvalidOperationException("SESSION_ALREADY_ACTIVE");
        }
        try
        {
            if (!_dependencies.IsAdministrator()) throw new InvalidOperationException("ADMIN_REQUIRED");
            if (duration <= TimeSpan.Zero || duration > TimeSpan.FromMinutes(20)) throw new ArgumentOutOfRangeException(nameof(duration));
            if (!nativeSmoke)
            {
                if (profiles.Count is < 1 or > 8) throw new InvalidOperationException("PROFILE_COUNT");
                if (profiles.Select(p => p.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count() != profiles.Count
                    || profiles.Select(p => p.ExecutablePath).Distinct(StringComparer.OrdinalIgnoreCase).Count() != profiles.Count)
                    throw new InvalidOperationException("DUPLICATE_PROFILE_OR_IMAGE");
                foreach (var profile in profiles)
                {
                    if (string.IsNullOrWhiteSpace(profile.Id) || !Path.IsPathFullyQualified(profile.ExecutablePath)
                        || !string.Equals(Path.GetExtension(profile.ExecutablePath), ".exe", StringComparison.OrdinalIgnoreCase)
                        || !File.Exists(profile.ExecutablePath)) throw new InvalidOperationException("EXECUTABLE_REQUIRED");
                    _ = StrategyCatalog.Get(profile.StrategyId);
                }
            }
            await Task.Run(() => _dependencies.VerifyPackage(directory, token), token);
            if (_dependencies.HasConflicts()) throw new InvalidOperationException("CONFLICTING_ENGINE_ACTIVE");
            _singleInstance = _dependencies.AcquireLease();
            _stopping = false;
            _opened = _closed = 0;
            _loaded = _unloaded = false;
            _passed = _failed = 0;
            _failure = null;
            _budget = new FlowBudget();
            _telemetry = new SessionTelemetryAccumulator();
            _tcpTelemetry = new SessionTelemetryAccumulator();
            _components = new ApprovedApplicationComponents(profiles);
            _exchange = new ExchangeTelemetryCollector(profiles, approvedProfiles: () => _components.Profiles);
            _bindings = new ProfileBindingCollector(profiles, approvedProfiles: () => _components.Profiles);
            _tcp = new TcpDiagnosticCollector(); _tcpBudget.Clear();
            foreach (var entry in _tlsPrefixes.Values) entry.Prefix.Dispose();
            _tlsPrefixes.Clear();
            foreach (var entry in _hostRanges.Values) entry.Prefix.Dispose();
            _hostRanges.Clear();
            lock (_snapshotLock)
            {
                _profiles.Clear();
                foreach (var profile in profiles) _profiles[profile.Id] = new(profile.Id, "Waiting for verified IPv4 UDP", 0, 0);
            }
            _ownership = new ProcessOwnership(profiles, (profileId, identity) =>
                _bindings.Record(profileId, identity, "flow-exact-image+creation-time+capture-time"), () => _components.Profiles);
            _tcpOwnership = new TcpOwnership(profiles, (profileId, identity) =>
                _bindings.Record(profileId, identity, "tcp-table+exact-image+birth; mutation additionally requires capture history"), () => _components.Profiles);
            _packageLocks.AddRange(_dependencies.LockPackage(directory));
            _dependencies.VerifyPackage(directory, token);
            _library = _dependencies.LoadLibrary(Path.Combine(directory, "WinDivert.dll"));
            _loaded = true;
            var observeOnly = nativeSmoke || profiles.All(p => StrategyCatalog.Get(p.StrategyId).Mode == StrategyMode.Observe);
            var udpObserveOnly = nativeSmoke || profiles.All(p => !StrategyCatalog.HasUdp(StrategyCatalog.Get(p.StrategyId)));
            _telemetry.Start(udpObserveOnly);
            _tcpTelemetry.Start(false);
            var tcpEnabled = !nativeSmoke && loopbackSmokePort is null;
            var eventFilter = tcpEnabled ? "tcp or (udp and !ipv6)" : "udp and !ipv6";
            var flow = Open(nativeSmoke ? "false" : eventFilter, 2, 5);
            var socket = Open(nativeSmoke ? "false" : eventFilter, 3, 5);
            var networkFilter = nativeSmoke || tcpSmokePort is not null ? "false" : loopbackSmokePort is not null
                ? $"outbound and ip and udp and loopback and !impostor and ip.SrcAddr == 127.0.0.1 and ip.DstAddr == 127.0.0.1 and udp.DstPort == {loopbackSmokePort.Value}"
                : "outbound and ip and udp and !loopback and !impostor";
            var network = Open(networkFilter, 0, udpObserveOnly ? 5UL : 0UL);
            // Physical inbound packets are copied, never diverted or reinjected. WinDivert
            // reports loopback only as outbound, so diagnostic replies use an exact own
            // localhost server-source-port filter and are explicitly not WAN-inbound proof.
            var inboundFilter = tcpSmokePort is not null ? "false" : loopbackSmokePort is not null
                ? $"outbound and ip and udp and loopback and !impostor and ip.SrcAddr == 127.0.0.1 and ip.DstAddr == 127.0.0.1 and udp.SrcPort == {loopbackSmokePort.Value}"
                : "inbound and ip and udp and !loopback and !impostor";
            var inbound = nativeSmoke ? IntPtr.Zero : Open(inboundFilter, 0, 5);
            _workers.Add(StartWorker(() => ObserveEvents(flow), "FLOW"));
            _workers.Add(StartWorker(() => ObserveEvents(socket), "SOCKET"));
            _workers.Add(StartWorker(() => ProcessPackets(network, udpObserveOnly, loopbackSmokePort), "NETWORK"));
            if (!nativeSmoke)
                _workers.Add(StartWorker(() => ObserveInboundCopies(inbound), "INBOUND"));
            if (tcpEnabled)
            {
                var tcpFilter = tcpSmokePort is null ? "tcp and !loopback and !impostor"
                    : $"ip and tcp and loopback and !impostor and ip.SrcAddr == 127.0.0.1 and ip.DstAddr == 127.0.0.1 and (tcp.DstPort == {tcpSmokePort} or tcp.SrcPort == {tcpSmokePort})";
                // Observe before diversion. Copies have never been blocked; incoming TCP is never modified.
                // Passive only: include injected inbound copies rather than silently excluding their replies.
                // The active mutation filter retains !impostor to prevent reinjection loops.
                var tcpObserver = Open(tcpFilter.Replace(" and !impostor", ""), 0, 5, 100);
                _workers.Add(StartWorker(() => ObserveTcpCopies(tcpObserver), "TCP_OBSERVER"));
                if (profiles.Any(profile => StrategyCatalog.HasTls(StrategyCatalog.Get(profile.StrategyId))))
                {
                    var ports = tcpSmokePort is null ? "(tcp.DstPort == 443 or tcp.DstPort == 2053 or tcp.DstPort == 2083 or tcp.DstPort == 2087 or tcp.DstPort == 2096 or tcp.DstPort == 8443)"
                        : $"tcp.DstPort == {tcpSmokePort}";
                    var activeTcp = Open(tcpFilter + " and outbound and tcp.PayloadLength > 0 and " + ports, 0, 0);
                    _workers.Add(StartWorker(() => ProcessTcpPackets(activeTcp, tcpSmokePort), "TCP_ACTIVE"));
                }
                _tcp.Start(true);
            }
            // Measurement starts only after the observer handle and its worker exist.
            // Earlier queued captures remain unknown rather than retroactively attributed.
            _exchange.Start(!nativeSmoke);
            _running = true;
            _state = nativeSmoke ? "Native smoke: false filter" : "Running: UDP + TCP/TLS metadata; application results unverified";
            _deadline = new CancellationTokenSource();
            var deadlineToken = _deadline.Token;
            _ = Task.Run(async () =>
            {
                try { await _dependencies.DelayAsync(duration, deadlineToken); await StopAsync(); }
                catch (OperationCanceledException) { }
                catch (Exception ex) { Log($"AUTO_STOP_FAILED:{ex.GetType().Name}"); }
            });
            _callerCancellation = token.Register(() => _ = Task.Run(StopAsync));
            Log($"START:profiles={profiles.Count};mode={(observeOnly ? "observe" : "experimental")};seconds={(int)duration.TotalSeconds};UDP=IPv4;TCPObserver={tcpEnabled};TLSCandidate={profiles.Any(p => StrategyCatalog.HasTls(StrategyCatalog.Get(p.StrategyId)))}");
        }
        catch
        {
            await CleanupAsync();
            throw;
        }
        finally { _gate.Release(); }
    }

    private IntPtr Open(string filter, int layer, ulong flags, short priority = 0)
    {
        var handle = _library!.Open(filter, layer, priority, flags);
        if (handle == new IntPtr(-1) || handle == IntPtr.Zero)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        _handles.Add(handle);
        _opened++;
        return handle;
    }

    // WinDivertRecv blocks synchronously. Dedicated background workers avoid starving
    // later observers and async cleanup/probes behind permanently blocked pool tasks.
    private Task StartWorker(Action worker, string kind) => Task.Factory.StartNew(
        () => GuardWorker(worker, kind), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

    private void GuardWorker(Action worker, string kind)
    {
        try { worker(); }
        catch (Exception ex) { Fatal($"{kind}_WORKER_FAILED:{ex.GetType().Name}"); }
    }

    private void ObserveEvents(IntPtr handle)
    {
        while (_library!.Recv(handle, null, 0, out _, out var address))
        { _ownership!.Observe(address); _tcpOwnership!.Observe(address); }
        var error = Marshal.GetLastWin32Error();
        if (!_stopping) Fatal($"EVENT_RECEIVE_FAILED:{error}");
    }

    private void ProcessPackets(IntPtr handle, bool sniff, ushort? loopbackSmokePort)
    {
        var buffer = new byte[65535];
        while (_library!.Recv(handle, buffer, (uint)buffer.Length, out var size, out var address))
        {
            var processingStarted = Stopwatch.GetTimestamp();
            _telemetry.Capture();
            var attribution = PacketAttribution.Unknown;
            // Each diverted original is returned exactly once even if authorization or strategy fails.
            var original = buffer.AsSpan(0, checked((int)size)).ToArray();
            try
            {
                if (Ipv4UdpPacket.TryParse(original, out var packet) && packet is not null)
                {
                    var resolved = _ownership!.ResolveDetailed(packet.Flow, address.Timestamp);
                    attribution = resolved.Attribution;
                    var owned = resolved.Owned;
                    if (owned is not null)
                    {
                        _ownership.RecordAuthorizedOutbound(packet.Flow, owned, address.Timestamp);
                        _exchange.RecordOutbound(packet.Flow, owned, address.Timestamp, packet.TotalLength - packet.PayloadOffset);
                        Update(owned.Profile.Id, 1, 0, owned.Evidence);
                        var strategy = StrategyCatalog.Get(owned.Profile.StrategyId);
                        if (!_stopping && !sniff && StrategyCatalog.HasUdp(strategy) && original.Length <= 1200
                            && (IsPublicDestination(packet.Flow.DestinationAddress) || loopbackSmokePort is not null
                                && packet.Flow.SourceAddress == 0x7F000001 && packet.Flow.DestinationAddress == 0x7F000001
                                && packet.Flow.DestinationPort == loopbackSmokePort.Value)
                            && packet.Flow.DestinationPort is not (53 or 67 or 68 or 123 or 5353)
                            && _budget.TryConsume(packet.Flow, strategy.Id, DateTimeOffset.UtcNow, strategy.InitialPackets))
                        {
                            var fake = FakePacketBuilder.Build(original, strategy);
                            for (var index = 0; index < strategy.Repeats && !_stopping; index++)
                            {
                                // Recheck live ownership before each injection, not merely before building.
                                var current = _ownership.Resolve(packet.Flow, address.Timestamp);
                                if (current is null || current.Profile.Id != owned.Profile.Id
                                    || !OwnershipPolicy.SameIdentity(current.Identity, owned.Identity)) break;
                                var fakeAddress = address;
                                fakeAddress.Bits |= (1u << 21) | (1u << 23); // checksums supplied, including intentional bad UDP
                                if (!Send(handle, fake, ref fakeAddress, true)) break;
                                Update(owned.Profile.Id, 0, 1, owned.Evidence);
                            }
                        }
                    }
                }
            }
            catch (Exception ex) { Fatal($"PACKET_PROCESSING_FAILED:{ex.GetType().Name}"); }
            finally
            {
                try
                {
                    if (!sniff && !Send(handle, original, ref address)) Fatal("ORIGINAL_REINJECTION_FAILED");
                }
                finally
                {
                    _telemetry.PacketCompleted(attribution, sniff, address.Timestamp, processingStarted, Stopwatch.GetTimestamp());
                    Interlocked.Increment(ref _passed);
                }
            }
        }
        var error = Marshal.GetLastWin32Error();
        if (!_stopping) Fatal($"NETWORK_RECEIVE_FAILED:{error}");
    }

    private void ObserveInboundCopies(IntPtr handle)
    {
        var buffer = new byte[65535];
        while (_library!.Recv(handle, buffer, (uint)buffer.Length, out var size, out var address))
        {
            if (size > buffer.Length || !Ipv4UdpPacket.TryParse(buffer.AsSpan(0, checked((int)size)), out var packet) || packet is null)
                _exchange.RecordUnknownInbound();
            else
                _exchange.ObserveInbound(packet.Flow, address.Timestamp, (flow, captured) => _ownership!.Resolve(flow, captured), packet.TotalLength - packet.PayloadOffset);
            // SNIFF|RECV_ONLY: this copy has already passed. Never call Send here.
        }
        if (!_stopping) Fatal($"INBOUND_RECEIVE_FAILED:{Marshal.GetLastWin32Error()}");
    }

    private void ObserveTcpCopies(IntPtr handle)
    {
        var buffer = new byte[65535];
        while (_library!.Recv(handle, buffer, (uint)buffer.Length, out var size, out var address))
        {
            var bytes = buffer.AsSpan(0, checked((int)size));
            bool parsed = TcpPacket.TryParse(bytes, out var packet) && packet is not null;
            _tcp.ObserveCapture(parsed, address.Outbound, address.Impostor);
            if (!parsed) continue;
            var owner = _tcpOwnership!.Resolve(address.Outbound ? packet!.Flow : packet!.Flow.Reverse(), address.Timestamp, false);
            _tcp.Copy(packet!, bytes, owner, address.Outbound, address.Timestamp, address.Impostor);
        }
        if (!_stopping) Fatal($"TCP_OBSERVER_RECEIVE_FAILED:{Marshal.GetLastWin32Error()}");
    }
    private void ProcessTcpPackets(IntPtr handle, ushort? smokePort)
    {
        var buffer = new byte[65535];
        while (_library!.Recv(handle, buffer, (uint)buffer.Length, out var size, out var address))
        {
            var original = buffer.AsSpan(0, checked((int)size)).ToArray();
            var processingStarted = Stopwatch.GetTimestamp();
            _tcpTelemetry.Capture();
            bool replaced = false;
            var attribution = PacketAttribution.Unknown;
            try
            {
                if (!_stopping && TcpPacket.TryParse(original, out var packet) && packet is not null
                    && original.Length <= TlsClientHelloSplit.MaximumOriginalLength)
                {
                    var owner = _tcpOwnership!.Resolve(packet.Flow, address.Timestamp, true);
                    if (owner is not null) attribution = PacketAttribution.Authorized;
                    if (owner is not null && StrategyCatalog.HasTls(StrategyCatalog.Get(owner.Profile.StrategyId)))
                    {
                        var range = _tcp.ObserveDivertedOriginal(packet, original.AsSpan(packet.PayloadOffset), owner);
                        int realSegmentsSent = 0; bool tlsFakeSent = false;
                        bool publicRemote = packet.IsV6 ? (packet.Flow.Remote.A >> 29) == 1 : IsPublicDestination(packet.Flow.Remote.A);
                        var reason = "PRIVATE_REMOTE_UNCHANGED";
                        var prefixDecision = "PRIVATE_REMOTE_UNCHANGED";
                        var key = (packet.Flow, owner.Endpoint);
                        TlsHostRange? structuralRange = null;
                        if ((publicRemote || smokePort is not null) && FindTlsSplit(packet, owner, original.AsSpan(packet.PayloadOffset), out var split, out reason, smokePort is not null, out structuralRange))
                        {
                            prefixDecision = reason;
                            if (_tcpBudget.GetValueOrDefault(key) >= TlsClientHelloSplit.MaximumSplitsPerConnection || _tcpBudget.Count >= 4096 && !_tcpBudget.ContainsKey(key))
                                reason = "TCP_SPLIT_BUDGET_EXHAUSTED";
                            else
                            {
                                var strategy = StrategyCatalog.Get(owner.Profile.StrategyId);
                                var disorder = StrategyCatalog.IsDisorder(strategy); var hostFake = StrategyCatalog.IsHostFake(strategy);
                                IReadOnlyList<TcpWireStep> steps = [];
                                bool hostBuilt = !hostFake || (StrategyCatalog.IsStructuralHostFake(strategy)
                                    ? structuralRange is not null && TlsHostFakeSplit.TryBuildStructural(original, structuralRange, out steps, out reason, smokePort is not null)
                                    : TlsHostFakeSplit.TryBuild(original, out steps, out reason, smokePort is not null));
                                if (!hostBuilt)
                                {
                                    _tcp.SplitDecision(packet.Flow, owner, reason, false, 3,
                                        new(DateTimeOffset.UtcNow, range.Relation, range.RelativeSequence, packet.PayloadLength, prefixDecision, reason, 0, false, StructuralHostRange: structuralRange));
                                    continue; // finally returns original unchanged, no budget consumed.
                                }
                                if (!hostFake)
                                {
                                    var segments = disorder ? TlsClientHelloSplit.BuildDisorder(original, split) : TlsClientHelloSplit.Build(original, split);
                                    steps = segments.Select(bytes => new TcpWireStep(bytes, false)).ToArray();
                                    if (StrategyCatalog.HasTlsFake(strategy)) steps = [new(TlsFakePacket.Build(original), true), .. steps];
                                }
                                var recheck = _tcpOwnership.Resolve(packet.Flow, address.Timestamp, true);
                                if (recheck is not null && recheck.Endpoint == owner.Endpoint && OwnershipPolicy.SameIdentity(recheck.Identity, owner.Identity))
                                {
                                    _tcpBudget[key] = _tcpBudget.GetValueOrDefault(key) + 1;
                                    var splitAddress = address; splitAddress.Bits |= (1u << 21) | (1u << 22);
                                    var tlsFake = StrategyCatalog.HasTlsFake(strategy);
                                    bool allSent = true;
                                    foreach (var step in steps!)
                                    {
                                        // Do not send even a host-range fake under a reused/changed endpoint identity.
                                        var stillOwned = _tcpOwnership.Resolve(packet.Flow, address.Timestamp, true);
                                        if (stillOwned is null || stillOwned.Endpoint != owner.Endpoint || !OwnershipPolicy.SameIdentity(stillOwned.Identity, owner.Identity))
                                        { allSent = false; break; }
                                        if (!Send(handle, step.Packet, ref splitAddress, synthetic: step.Synthetic, tcp: true)) { allSent = false; break; }
                                        if (step.Synthetic)
                                        {
                                            tlsFakeSent = true;
                                            _tcp.TlsFakeSent(packet.Flow, owner);
                                            lock (_snapshotLock) { var old = _profiles[owner.Profile.Id]; _profiles[owner.Profile.Id] = old with { TlsFakePackets = old.TlsFakePackets + 1 }; }
                                        }
                                        else realSegmentsSent++;
                                    }
                                    replaced = allSent && realSegmentsSent == StrategyCatalog.TlsSegmentCount(strategy) && (!tlsFake || tlsFakeSent);
                                    reason = replaced ? hostFake ? "HOSTFAKE_TS_ALTORDER_STREAM_PRESERVED" : tlsFake ? "TLS_FAKE_HALF_SEQ_THEN_ORDERED_SPLIT" : disorder ? "DISORDER_THREE_REAL_SEGMENTS_STREAM_PRESERVED" : "SPLIT_TWO_REAL_SEGMENTS_STREAM_PRESERVED" : "TCP_SPLIT_SEND_FAILED";
                                    if (!replaced) Fatal(reason);
                                    if (replaced) lock (_snapshotLock)
                                        {
                                            var old = _profiles[owner.Profile.Id];
                                            _profiles[owner.Profile.Id] = old with { TcpSplitPackets = old.TcpSplitPackets + 1, State = "Verified process TLS split; Discord loading/voice unverified" };
                                        }
                                }
                                else reason = "TCP_OWNER_CHANGED_UNCHANGED";
                            }
                        }
                        if (prefixDecision == "PRIVATE_REMOTE_UNCHANGED") prefixDecision = reason;
                        _tcp.SplitDecision(packet.Flow, owner, reason, replaced, StrategyCatalog.TlsSegmentCount(StrategyCatalog.Get(owner.Profile.StrategyId)),
                            new(DateTimeOffset.UtcNow - TimeSpan.FromSeconds(Math.Clamp((Stopwatch.GetTimestamp() - address.Timestamp) / (double)Stopwatch.Frequency, 0, 1200)), range.Relation, range.RelativeSequence,
                                packet.PayloadLength, prefixDecision, reason, realSegmentsSent, replaced, tlsFakeSent, structuralRange));
                    }
                }
            }
            catch (ArgumentException) { /* Unsupported flags/format: return untouched original. */ }
            catch (Exception ex) { Fatal($"TCP_PROCESSING_FAILED:{ex.GetType().Name}"); }
            finally
            {
                // If a split send partially failed, send the original range as TCP retransmission;
                // the receiver deduplicates identical sequence bytes. This is failure, never verified success.
                try { if (!replaced && !Send(handle, original, ref address, tcp: true)) Fatal("TCP_ORIGINAL_REINJECTION_FAILED"); }
                finally
                {
                    _tcpTelemetry.PacketCompleted(attribution, false, address.Timestamp, processingStarted, Stopwatch.GetTimestamp());
                    Interlocked.Increment(ref _passed);
                }
            }
        }
        if (!_stopping) Fatal($"TCP_RECEIVE_FAILED:{Marshal.GetLastWin32Error()}");
    }

    public static bool IsPublicDestination(uint address) =>
        address != 0 && address >> 24 != 0 && address >> 24 != 10 && address >> 24 != 127
        && address >> 24 < 224 && address >> 16 != 0xA9FE && address >> 16 != 0xC0A8
        && (address >> 20) != 0xAC1 && (address >> 22) != 0x191
        && address >> 8 != 0xC00000 && address >> 8 != 0xC00002 && address >> 8 != 0xC05863
        && address >> 8 != 0xC63364 && address >> 8 != 0xCB0071 && address >> 17 != 0x6309;

    private bool Send(IntPtr handle, byte[] packet, ref DivertAddress address, bool synthetic = false, bool tcp = false)
    {
        bool success;
        try { success = _library!.Send(handle, packet, (uint)packet.Length, out var sent, ref address) && sent == packet.Length; }
        catch
        {
            (tcp ? _tcpTelemetry : _telemetry).SendCompleted(synthetic, false);
            Interlocked.Increment(ref _failed);
            throw;
        }
        (tcp ? _tcpTelemetry : _telemetry).SendCompleted(synthetic, success);
        if (success) return true;
        Interlocked.Increment(ref _failed);
        Log($"SEND_FAILED:{Marshal.GetLastWin32Error()}");
        return false;
    }
    private void Update(string id, long observed, long fake, string evidence)
    {
        lock (_snapshotLock)
        {
            var old = _profiles[id];
            _profiles[id] = old with { State = $"Verified process UDP ({evidence}); game/voice unverified", ObservedPackets = old.ObservedPackets + observed, FakePackets = old.FakePackets + fake };
        }
    }
    private void Fatal(string code)
    {
        Log(code);
        _failure ??= code;
        _state = code;
        _stopping = true;
        _ = Task.Run(StopAsync);
    }
    private void Log(string message) { try { _safeLog(message); } catch { /* Logging must never strand a diverted packet. */ } }

    public SessionSnapshot Snapshot()
    {
        lock (_snapshotLock) return new(_running, _state, _profiles.Values.ToArray(), Interlocked.Read(ref _passed), Interlocked.Read(ref _failed));
    }
    public NativeEvidence Evidence => new(_opened, _closed, _loaded, _unloaded, !_running && _handles.Count == 0 && (!_loaded || _unloaded));
    public SessionTelemetrySnapshot Telemetry() => _telemetry.Snapshot(_bindings.Snapshot(), _bindings.Dropped) with
    {
        Tcp = _tcpTelemetry.Snapshot([], 0) with { CounterScope = "Diverted TCP originals only; ReinjectedOriginals counts real sends including replacement segments; observer copies are in TcpDiagnostics" }
    };
    public ExchangeTelemetrySnapshot ExchangeTelemetry() => _exchange.Snapshot();
    public TcpDiagnosticSnapshot TcpDiagnostics() => _tcp.Snapshot() with { OwnershipResolutionCalls = _tcpOwnership?.ResolutionCounts(), ComponentEvents = _tcpOwnership?.ComponentEvents() };
    public IReadOnlyList<ApplicationComponentEvidence> ComponentEvidence() => _components?.Evidence ?? [];
    public IReadOnlyList<AppProfile> ApprovedProfiles() => _components?.Profiles ?? [];
    public void RefreshApprovedComponents() { _components?.Refresh(); _bindings.PrepareHashes(); }
    public void SampleCurrentTcpTables() => _tcp.SampleCurrentTables(_components?.Profiles ?? [], _components?.Profiles);

    private bool FindTlsSplit(TcpPacket packet, OwnedPacket owner, ReadOnlySpan<byte> payload, out int split, out string reason, bool diagnostic, out TlsHostRange? structuralRange)
    {
        structuralRange = null;
        var expanded = StrategyCatalog.IsHostFake(StrategyCatalog.Get(owner.Profile.StrategyId));
        // Expanded provider outer-SNI permission is exclusively for the trusted Discord install, never arbitrary profiles.
        if (expanded && !diagnostic && (_components is null || !_components.IsTrustedDiscordProfile(owner.Profile.Id)))
        { split = 0; reason = "HOSTFAKE_REQUIRES_TRUSTED_DISCORD_PROFILE"; return false; }
        if (StrategyCatalog.IsStructuralHostFake(StrategyCatalog.Get(owner.Profile.StrategyId)))
        {
            split = 0; reason = "HOST_RANGE_NO_CONTEXT";
            if (payload.IsEmpty) return false;
            long stamp = Stopwatch.GetTimestamp(); var rangeIdentity = (packet.Flow, owner.Endpoint, owner.Identity.CreationTime);
            // Retain bounded metadata/tombstones until Stop. Expiry must never recreate
            // the same endpoint context and reset its deadline on a retransmission.
            if (!_hostRanges.TryGetValue(rangeIdentity, out var rangeEntry))
            {
                if (payload[0] != 22) return false;
                if (_hostRanges.Count >= 128) { reason = "HOST_RANGE_CACHE_LIMIT"; return false; }
                rangeEntry = (new(), stamp); _hostRanges.Add(rangeIdentity, rangeEntry);
            }
            if (!rangeEntry.Prefix.TryCurrent(packet.Sequence, payload, Stopwatch.GetElapsedTime(rangeEntry.Started, stamp), out structuralRange, out reason)) return false;
            if (!(TlsHostFakeSplit.Allowed(structuralRange!.Sni) || diagnostic && structuralRange.Sni.HostSha256 == TlsSniEvidence.FromHost("localhost").HostSha256))
            { structuralRange = null; reason = "SNI_NOT_DISCORD_OR_CONFIRMED_OUTER"; return false; }
            split = structuralRange.Start + structuralRange.Length / 2; return true;
        }
        // Original complete prefixes and retransmissions use the same bounded per-endpoint split budget.
        if (TlsClientHelloSplit.TryFindSplit(payload, out split, out reason, out var sni, diagnostic || expanded))
        {
            if (!diagnostic && expanded && !TlsHostFakeSplit.Allowed(sni)) { split = 0; reason = "SNI_NOT_DISCORD_OR_CONFIRMED_OUTER"; return false; }
            return true;
        }
        if (reason == "SNI_NOT_DISCORD" || payload.IsEmpty) return false;
        var now = Stopwatch.GetTimestamp();
        foreach (var key in _tlsPrefixes.Where(pair => Stopwatch.GetElapsedTime(pair.Value.Started, now) >= TlsPrefixAssembler.MaximumLifetime).Select(pair => pair.Key).ToArray())
        { _tlsPrefixes[key].Prefix.Dispose(); _tlsPrefixes.Remove(key); }
        var identity = (packet.Flow, owner.Endpoint, owner.Identity.CreationTime);
        if (!_tlsPrefixes.TryGetValue(identity, out var entry))
        {
            if (payload[0] != 22) return false;
            if (_tlsPrefixes.Count >= 128) { reason = "TLS_PREFIX_CACHE_LIMIT"; return false; }
            entry = (new TlsPrefixAssembler(), now); _tlsPrefixes.Add(identity, entry);
        }
        bool found = entry.Prefix.TryFindCurrentSplit(packet.Sequence, payload, Stopwatch.GetElapsedTime(entry.Started, now), out split, out reason, diagnostic || expanded);
        if (found && !diagnostic && expanded && !TlsHostFakeSplit.Allowed(entry.Prefix.Sni)) { split = 0; reason = "SNI_NOT_DISCORD_OR_CONFIRMED_OUTER"; return false; }
        return found;
    }
    public ExchangeObservationMark CaptureUserEventObservation() => _exchange.CaptureUserEventObservation();
    public UserEventExchangeTelemetry UserEventTelemetry(string markId) => _exchange.UserEventTelemetry(markId);
    public async Task StopAsync()
    {
        await _gate.WaitAsync();
        try { await CleanupAsync(); }
        finally { _gate.Release(); }
    }
    private async Task CleanupAsync()
    {
        _stopping = true;
        _deadline?.Cancel();
        _callerCancellation.Unregister();
        if (_library is not null)
        {
            // Stop new queueing; keep Send usable while returning already captured originals.
            foreach (var handle in _handles)
            {
                try
                {
                    if (!_library.Shutdown(handle, 1)) Log($"SHUTDOWN_FAILED:{Marshal.GetLastWin32Error()}");
                }
                catch (Exception ex) { Log($"SHUTDOWN_FAILED:{ex.GetType().Name}"); }
            }
            try { await Task.WhenAll(_workers).WaitAsync(TimeSpan.FromSeconds(10)); }
            catch (TimeoutException)
            {
                // Closing removes own diversion even if a faulty receive cannot drain. Do not unload
                // delegates until the threads have returned; don't claim an unconfirmed stop succeeded.
                foreach (var handle in _handles.ToArray()) TryClose(handle);
                try { await Task.WhenAll(_workers).WaitAsync(TimeSpan.FromSeconds(5)); }
                catch { throw new InvalidOperationException("STOP_INCOMPLETE_DLL_RETAINED"); }
                _failure ??= "STOP_DRAIN_TIMEOUT_QUEUE_MAY_HAVE_DROPPED";
            }
            catch (Exception ex) { _failure ??= $"WORKER_FAILED:{ex.GetType().Name}"; }
            var closeFailed = false;
            foreach (var handle in _handles.ToArray())
            {
                if (!TryClose(handle)) closeFailed = true;
            }
            if (closeFailed) throw new InvalidOperationException("STOP_CLOSE_FAILED_DLL_RETAINED");
            _workers.Clear();
            foreach (var entry in _tlsPrefixes.Values) entry.Prefix.Dispose();
            _tlsPrefixes.Clear();
            foreach (var entry in _hostRanges.Values) entry.Prefix.Dispose();
            _hostRanges.Clear();
            _library.Dispose();
            _library = null;
            _unloaded = true;
            Log($"STOP:opened={_opened};closed={_closed};DLLUnloaded=true;sendFailures={_failed}");
        }
        foreach (var file in _packageLocks) file.Dispose();
        _packageLocks.Clear();
        _deadline?.Dispose();
        _deadline = null;
        _singleInstance?.Dispose();
        _singleInstance = null;
        _telemetry.Stop();
        _tcpTelemetry.Stop();
        _exchange.Stop(_failure is null);
        _tcp.Stop(_failure is null);
        _state = _failure is null ? "Stopped; own interception released; results unverified" : $"Stopped after failure: {_failure}";
        // Publish terminal state/telemetry before the volatile stop flag makes rollback observable.
        _running = false;
    }
    private bool TryClose(IntPtr handle)
    {
        try
        {
            if (_library!.Close(handle))
            {
                _handles.Remove(handle);
                _closed++;
                return true;
            }
            Log($"CLOSE_FAILED:{Marshal.GetLastWin32Error()}");
        }
        catch (Exception ex) { Log($"CLOSE_FAILED:{ex.GetType().Name}"); }
        return false;
    }
    public async ValueTask DisposeAsync() => await StopAsync();
}
