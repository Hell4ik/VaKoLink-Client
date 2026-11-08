using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using System.Security.Cryptography;
using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public sealed record ProxyTunEvidence(string Core, string CoreVersion, string CoreSha256, bool Running, int? CoreProcessId, string? Failure,
    bool GeneralTunCapture, bool OwnAntiDpiActive, bool PhysicalBindingConfigured, bool LoopbackRouteExcluded, bool CoreLocalProxySocketObserved,
    bool NativeDnsDisabled, bool ExistingSystemProxyPreserved, bool TechnicalProbeMode, bool GracefulSignal, bool ForcedTermination,
    bool CoreExited, bool SecretConfigurationDeleted, bool MarkerRemoved, bool CleanupConfirmed, IReadOnlyDictionary<string, bool> BaselineAfter,
    IReadOnlyList<TunFlowEvidence> Flows, int ApiPolls, int ApiFailures, int HistoryDropped,
    bool CoreCreated = false, int? CoreExitCode = null, string TerminationInitiator = "NotStarted", string CleanupBasis = "NotChecked",
    AionTunPlan.PinEvidence? FilePins = null, IReadOnlyList<TunLifecycleEvent>? Lifecycle = null,
    string StderrStatus = "NotStarted", int StderrCapturedBytes = 0, bool StderrTruncated = false,
    ProxyCleanupAssessment? CleanupAssessment = null, bool PreviousJournalPending = false,
    string Coverage = "Bounded 250ms active connection snapshots; short/closed-between-polls flows can be missed. TUN ACK is client-facing TCP termination, not game receiver acceptance. Unknown owners final=direct; DNS direct even for game; existing explicit HTTP/SOCKS proxies are NOT overridden.",
    IReadOnlyList<NetworkIsolationCheck>? StartupIsolation = null, IReadOnlyList<NetworkCleanupCheck>? CleanupChecks = null,
    bool? SystemProxyInitiallyEnabled = null, ProxyProbe? StartupProxyProbe = null, string? ProxyEndpointIdentitySha256 = null,
    IReadOnlyList<BaselineStabilityCheck>? BaselineStability = null, ProxyProbe? LatestHealthProxyProbe = null);

public sealed class ProxyTunSession : IAsyncDisposable
{
    private readonly LocalProxyEndpoint _localProxy; private readonly JsonObject _capsule; private readonly AppProfile _main; private readonly object _gate = new();
    private readonly SemaphoreSlim _stop = new(1, 1); private readonly Dictionary<string, TunFlowEvidence> _flows = new();
    private readonly string _engine, _networkScript; private readonly bool _technical;
    private readonly bool _observe; private IDisposable? _lease; private readonly ApiFailureBudget _apiBudget = new();
    private TunChildProcess? _child; private FileStream? _coreLock, _mainLock, _marker;
    private HttpClient? _api; private Task? _poller; private CancellationTokenSource? _pollCancel; private JsonObject? _baseline, _during, _plan;
    private bool _ownsMarker; private ProxyCleanupAssessment? _cleanupAssessment; public JsonObject? Recovery { get; private set; }
    private string? _operation, _config, _failure; private bool _running, _excluded, _physicalSocket, _proxy, _clean, _secretDeleted, _markerRemoved;
    private bool _graceful, _forced, _exited; private int _apiPort, _probePort, _polls, _apiFails, _historyDropped; private string _apiSecret = "";
    private int? _pid; private IReadOnlyDictionary<string, bool> _comparison = new Dictionary<string, bool>();
    private readonly Stopwatch _lifecycleClock = Stopwatch.StartNew(); private readonly List<TunLifecycleEvent> _events = [];
    private readonly List<NetworkIsolationCheck> _isolation = []; private readonly List<NetworkCleanupCheck> _cleanupChecks = [];
    private bool? _systemProxyInitiallyEnabled;
    private ProxyProbe? _startupProxyProbe;
    private ProxyProbe? _healthProxyProbe;
    private readonly List<BaselineStabilityCheck> _baselineStability = [];
    private DateTimeOffset _lastProxyProbe; private int _proxyHealthFailures;
    private AionTunPlan.PinEvidence? _pins; private bool _created; private int? _exitCode;
    private string _termination = "NotStarted", _stderrStatus = "NotStarted"; private int _stderrBytes; private bool _stderrTruncated;
    private readonly IReadOnlyList<DiscordComponentPin> _discord;
    private readonly List<FileStream> _discordLocks = []; private int _discordProbePort; private MediaTimeline? _media;
    private Task? _discordProbeTask; private DateTimeOffset _lastDiscordProbe, _lastMedia, _lastIdentity;
    private object? _discordUdpProof; private string? _discordWarning; private string? _mediaFolder;
    public object DiscordEvidence => new { Enabled = _discord.Count > 0, Profile = _discord.Count > 0 ? DiscordMediaProfile.Id : "off",
        ApprovedComponents = _discord.Select(p => new { Component = "Discord.exe", PathSha256 = AionTunPlan.Hash(p.Path), p.Sha256 }),
        UdpChainProbe = _discordUdpProof, Warning = _discordWarning, TimelineDirectory = _mediaFolder is null ? null : Path.GetFileName(_mediaFolder), Timeline = _media?.Evidence,
        TcpPolicy = "Unchanged: direct inside core; application may independently use system proxy", AuthOrKeyRotationObserved = false, NativeQueueCountersAvailable = false };
    public string DiscordStatus => _discord.Count == 0 ? "Discord-профиль выключен · прежний режим Aion" :
        _discordWarning is not null ? "UDP-проверка: " + _discordWarning + " · маршрут не переключался" :
        _discordUdpProof is null ? "Проверяем UDP через всю цепочку…" : "UDP через V2rayN проверен · голос/видео ещё требуют пользовательской проверки";
    public void MarkMedia(string code) { _media?.Record("UserSymptom", new { Code = code, Current = DiscordEvidence }); }
    private void Event(string stage) { lock (_gate) { if (_events.Count >= 2048) _events.RemoveAt(32); _events.Add(new(stage, DateTimeOffset.UtcNow, _lifecycleClock.ElapsedMilliseconds)); } }
    public string? ConfigurationSha256 { get; private set; }
    public GamePassiveTrace Observer { get; }
    public ProxyTunSession(LocalProxyEndpoint proxy, string main, string hash, string networkScript, bool technical = false, IReadOnlyList<DiscordComponentPin>? discord = null)
    {
        _localProxy = proxy; _capsule = new JsonObject { ["MainPath"] = main, ["MainSHA256"] = hash, ["CoreSHA256"] = AionTunPlan.CoreSha256 };
        _main = new("aion2", "Aion 2", main, "observe"); _engine = ""; _networkScript = networkScript; _technical = technical; _observe = false;
        Observer = new(new[] { _main }, detailedAion: true, postCloseTail: true);
        _discord = discord ?? [];
    }
    public ProxyTunEvidence Evidence
    {
        get
        {
            lock (_gate) return new("sing-box (third-party transport, NOT direct AntiDPI)", AionTunPlan.CoreVersion,
        AionTunPlan.CoreSha256, _running, _pid, _failure, true, false, _baseline is not null, _excluded, _physicalSocket, true, _proxy, _technical,
        _graceful, _forced, _exited, _secretDeleted, _markerRemoved, _clean, new Dictionary<string, bool>(_comparison), _flows.Values.ToArray(), _polls, _apiFails, _historyDropped,
        _created, _exitCode, _termination, _baseline is null ? "NoNativeMutationAttempted_PreviousJournalNotOwned" : "OwnedFootprintVerified_GlobalComparisonSeparate",
        _pins, _events.ToArray(), _stderrStatus, _stderrBytes, _stderrTruncated, _cleanupAssessment, File.Exists(ProxyJournal.MarkerPath) && !_ownsMarker,
        StartupIsolation: _isolation.ToArray(), CleanupChecks: _cleanupChecks.ToArray(), SystemProxyInitiallyEnabled: _systemProxyInitiallyEnabled,
        StartupProxyProbe: _startupProxyProbe, ProxyEndpointIdentitySha256: ProxyEndpointRefresh.Identity(_localProxy), BaselineStability: _baselineStability.ToArray(),
        LatestHealthProxyProbe: _healthProxyProbe);
        }
    }
    private static int FreePort() { var l = new TcpListener(IPAddress.Loopback, 0); l.Start(); int p = ((IPEndPoint)l.LocalEndpoint).Port; l.Stop(); return p; }
    public static async Task<JsonObject> SnapshotAsync(string script)
    {
        var psi = new ProcessStartInfo("powershell.exe") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        // A PS7 host can export PS7-only modules; Windows PowerShell must use its own OS modules.
        psi.Environment["PSModulePath"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\WindowsPowerShell\v1.0\Modules") + ";" + Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"WindowsPowerShell\Modules");
        foreach (var a in new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script }) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi) ?? throw new IOException("TUN_SNAPSHOT_START"); var output = p.StandardOutput.ReadToEndAsync(); var error = p.StandardError.ReadToEndAsync();
        try { await p.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30)); }
        catch { p.Kill(); throw new IOException("TUN_SNAPSHOT_TIMEOUT"); }
        await error; var json = await output;
        if (p.ExitCode != 0 || json.Length > 1_000_000) throw new IOException("TUN_SNAPSHOT_FAILED");
        var snapshot = JsonNode.Parse(json)!.AsObject();
        snapshot["NativeInterfaces"] = NativeInterfaceIdentity.Capture(snapshot["Adapters"]!.AsArray().Select(n => (int)n!["InterfaceIndex"]!));
        return snapshot;
    }
    public static IReadOnlyDictionary<string, bool> Compare(JsonObject before, JsonObject after) => new[] { "Adapters", "Routes", "Addresses", "Interfaces", "DNS", "Firewall", "Proxy", "SourceRuntimeSHA" }
        .ToDictionary(k => k, k => ProxyNetworkIsolation.Equivalent(before[k], after[k]));
    public static Task<JsonObject> RecoverJournalAsync(string script, IReadOnlyList<LocalProxyMember>? proxyMembers = null) => ProxyJournal.RecoverAsync(script, proxyMembers);
    public async Task StartAsync()
    {
        try
        {
            Event("PreflightStarted");
            _localProxy.VerifyAlive();
            if (!RuntimePreflight.IsAdministrator() || RuntimePreflight.GetConflicts().Count != 0 || Process.GetProcessesByName("sing-box").Any(p => !_localProxy.Members.Any(m => m.Pid == p.Id))
                || Process.GetProcessesByName("AION2").Length != 0) throw new IOException("TUN_PREFLIGHT_CONFLICT");
            TunPrivateStore.VerifyImagePath(_main.ExecutablePath); TunPrivateStore.VerifyImagePath(AionTunPlan.CorePath);
            string expectedMain = (string?)_capsule["MainSHA256"] ?? "";
            _pins = new(AionTunPlan.CoreSha256, AionTunPlan.FileHash(AionTunPlan.CorePath), expectedMain,
                AionTunPlan.FileHash(_main.ExecutablePath), GameComponentTrust.IsSignedNcImage(_main.ExecutablePath),
                string.Equals((string?)_capsule["MainPath"], _main.ExecutablePath, StringComparison.OrdinalIgnoreCase),
                (string?)_capsule["CoreSHA256"] == AionTunPlan.CoreSha256 && System.Text.RegularExpressions.Regex.IsMatch(expectedMain, "^[A-F0-9]{64}$"));
            if (AionTunPlan.PinFailure(_pins) is { } failure) throw new IOException(failure);
            Event("FilePinsAndSignatureVerified");
            TunPrivateStore.EnsurePrivate(ProxyTunPlan.Root);
            string markerPath = Path.Combine(ProxyTunPlan.Root, "active-operation.json");
            if (File.Exists(markerPath)) { Event("PreviousJournalInspectionStarted"); Recovery = await RecoverJournalAsync(_networkScript, _localProxy.Members); Event("PreviousJournalSafelyReleased"); }
            var proxyProbe = _startupProxyProbe = await LocalProxy.ProbeAsync(_localProxy);
            if (!proxyProbe.Ready) throw new IOException(proxyProbe.Failure ?? "PROXY_NOT_READY"); Event("LocalProxyTcpUdpVerified");
            Event("BaselineReadOnlyStabilityStarted");
            _baseline = await ProxyBaselineStability.CaptureAsync(() => SnapshotAsync(_networkScript), check =>
            {
                lock (_gate) _baselineStability.Add(check);
                Event(check.Stable ? "BaselineReadOnlyStable" : "BaselineReadOnlyChanging");
            });
            Event("BaselineCaptured");
            if ((bool?)_baseline["V2rayTunEnabled"] == true || (bool?)_baseline["Physical"]?["Hardware"] != true
                || _baseline["Adapters"]!.AsArray().Any(a => (string?)a?["Name"] == ProxyTunPlan.AdapterName || (string?)a?["Name"] == "xray_tun")
                || _baseline["Routes"]!.AsArray().Any(r => (string?)r?["DestinationPrefix"] is "0.0.0.0/1" or "128.0.0.0/1" or "::/1" or "8000::/1")) throw new IOException("TUN_EXISTING_TUN_OR_DEFAULT_NOT_PHYSICAL");
            _systemProxyInitiallyEnabled = (int?)_baseline["Proxy"]?["Enable"] == 1;
            string physical = (string)_baseline["Physical"]!["Name"]!;
            string loopback = (string?)_baseline["LoopbackInterface"] ?? throw new IOException("TUN_LOOPBACK_INTERFACE_UNKNOWN");
            _coreLock = new(AionTunPlan.CorePath, FileMode.Open, FileAccess.Read, FileShare.Read); _mainLock = new(_main.ExecutablePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            foreach (var pin in _discord)
            {
                TunPrivateStore.VerifyImagePath(pin.Path); _discordLocks.Add(new(pin.Path, FileMode.Open, FileAccess.Read, FileShare.Read));
                if (AionTunPlan.FileHash(pin.Path) != pin.Sha256 || !DiscordMediaProfile.Discover().Contains(pin)) throw new IOException("DISCORD_UPDATED_RECHECK_REQUIRED");
            }
            if (AionTunPlan.FileHash(AionTunPlan.CorePath) != AionTunPlan.CoreSha256 || AionTunPlan.FileHash(_main.ExecutablePath) != expectedMain) throw new IOException("TUN_LOCKED_IMAGE_CHANGED");
            if (!_observe) _lease = new SessionDependencies().AcquireLease();
            _operation = Path.Combine(ProxyTunPlan.Root, Guid.NewGuid().ToString("N")); TunPrivateStore.EnsurePrivate(_operation);
            TunPrivateStore.WriteProtected(Path.Combine(_operation, "baseline.dpapi"), _baseline.ToJsonString());
            _marker = new(markerPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read); _ownsMarker = true; var markerBytes = Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(new { Operation = Path.GetFileName(_operation), ParentPid = Environment.ProcessId, ParentBirthUtc = Process.GetCurrentProcess().StartTime.ToUniversalTime(), StartedUtc = DateTimeOffset.UtcNow }));
            _marker.Write(markerBytes); _marker.Flush(true);
            _apiPort = FreePort(); _probePort = _technical ? FreePort() : 0; _apiSecret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            if (_discord.Count > 0) { _discordProbePort = FreePort(); _mediaFolder = Path.Combine(ProxyTunPlan.Root, "Reports", "media-" + Path.GetFileName(_operation)); _media = new(_mediaFolder); _media.Record("ProfileStarted", new { Profile = DiscordMediaProfile.Id, SystemProxyEnabled = (int?)_baseline["Proxy"]?["Enable"] == 1, Evidence = DiscordEvidence, Processes = DiscordMediaProfile.ProcessEvidence(_discord) }); }
            var config = ProxyTunPlan.Build(_localProxy, _main.ExecutablePath, physical, loopback, ProxyTunPlan.ChooseAddress(_baseline), _apiPort, _apiSecret, _probePort, ProxyTunPlan.ChooseIpv6Address(_baseline), _discord, _discordProbePort);
            _plan = config;
            _config = Path.Combine(_operation, "run-config.json"); await File.WriteAllTextAsync(_config, config.ToJsonString()); ConfigurationSha256 = AionTunPlan.FileHash(_config);
            TunPrivateStore.WriteProtected(Path.Combine(_operation, "configuration.dpapi"), config.ToJsonString());
            await CheckAsync(_config);
            _localProxy.VerifyAlive(); VerifyListenerPresent();
            Event("ConfigurationCheckPassed");
            if (_observe) await Observer.StartAsync(_engine, CancellationToken.None);
            Event(_observe ? "PassiveObserverStarted" : "TransportOnly_NoWinDivert");
            _child = new(); _child.Start(_config); _pid = _child.Process.Id; _created = true; _stderrStatus = "PrivateCaptureActive"; Event("CoreProcessCreatedAndResumed");
            _api = new(new HttpClientHandler { UseProxy = false }) { BaseAddress = new Uri("http://127.0.0.1:" + _apiPort), Timeout = TimeSpan.FromSeconds(2) };
            _api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _apiSecret);
            var ready = Stopwatch.StartNew(); bool apiReady = false;
            while (ready.Elapsed < TimeSpan.FromSeconds(15) && !_child.Process.HasExited)
            { try { await PollAsync(); apiReady = true; break; } catch (IOException ex) when (ex.Message == "TUN_NON_GAME_NODE_ROUTE") { throw; } catch { await Task.Delay(200); } }
            if (!apiReady) throw new IOException(_child.Process.HasExited ? "TUN_CORE_EXITED_BEFORE_API" : "TUN_CORE_API_NOT_READY");
            Event("LocalApiReady");
            for (int snapshot = 1; snapshot <= ProxyNetworkIsolation.MaximumStartupSnapshots; snapshot++)
            {
                if (snapshot > 1)
                {
                    Event("StartupIsolationReadOnlyRecheck");
                    await Task.Delay(ProxyNetworkIsolation.RecheckDelayMilliseconds);
                    _localProxy.VerifyAlive(); VerifyListenerPresent();
                    if (_child.Process.HasExited) throw new IOException("TUN_CORE_EXITED_DURING_ISOLATION");
                }
                var active = await SnapshotAsync(_networkScript); _during = active;
                // Persist before validation, including failed startup; raw values remain CurrentUser-DPAPI protected.
                TunPrivateStore.WriteProtected(Path.Combine(_operation, "during.dpapi"), active.ToJsonString());
                var own = active["Adapters"]!.AsArray().Where(a => (string?)a?["Name"] == ProxyTunPlan.AdapterName).ToArray();
                if (own.Length != 1 || (bool?)own[0]?["HardwareInterface"] != false) throw new IOException("TUN_ADAPTER_NOT_UNIQUE");
                int ownIndex = (int)own[0]!["InterfaceIndex"]!;
                if (snapshot == 1) Event("TunAdapterObserved");
                var ownRoutes = active["Routes"]!.AsArray().Where(r => (int?)r?["InterfaceIndex"] == ownIndex).ToArray();
                if (ownRoutes.Length == 0 || !ownRoutes.Any(r => PrefixMatches("2606:4700::1111", (string?)r?["DestinationPrefix"]))
                    || !ownRoutes.Any(r => PrefixMatches("1.1.1.1", (string?)r?["DestinationPrefix"]))) throw new IOException("TUN_ROUTES_NOT_OBSERVED");
                var check = ProxyNetworkIsolation.Evaluate(_baseline, active, ownIndex, _localProxy.Host, snapshot, _lifecycleClock.ElapsedMilliseconds);
                lock (_gate) _isolation.Add(check);
                _excluded = check.Predicates.Single(p => p.Id == "LOCAL_PROXY_ROUTE_EXCLUDED").Passed;
                _proxy = check.Predicates.Single(p => p.Id == "SYSTEM_PROXY_UNCHANGED").Passed;
                Event(check.Passed ? "StartupIsolationPassed" : "StartupIsolationMismatch_" + check.FailureCode);
                if (check.Passed) break;
                // Never wait on a possible proxy loop, reused index, proxy change or firewall change.
                if (!ProxyNetworkIsolation.CanRecheck(check)) throw new IOException(check.FailureCode);
            }
            if (_discord.Count > 0) { await CheckDiscordUdpAsync(); if (_discordWarning is not null) throw new IOException("DISCORD_UDP_CHAIN_NOT_VERIFIED"); }
            _running = true; Event("TransportReadyForGame"); _pollCancel = new(); _poller = Task.Run(async () =>
            {
                while (!_pollCancel.IsCancellationRequested)
                {
                    try
                    {
                        _localProxy.VerifyAlive(); VerifyListenerPresent(); await PollAsync(); _apiBudget.Success(); ObserveLocalProxySocket(); if ((_observe && !Observer.Evidence.Running) || _child.Process.HasExited) throw new IOException("TUN_COMPONENT_STOPPED");
                        if (_discord.Count > 0 && DateTimeOffset.UtcNow - _lastDiscordProbe > TimeSpan.FromSeconds(30) && (_discordProbeTask is null || _discordProbeTask.IsCompleted))
                        { _lastDiscordProbe = DateTimeOffset.UtcNow; _discordProbeTask = Task.Run(CheckDiscordUdpAsync); }
                        if (DateTimeOffset.UtcNow - _lastProxyProbe > TimeSpan.FromSeconds(30))
                        {
                            var health = _healthProxyProbe = await LocalProxy.ProbeAsync(_localProxy); _lastProxyProbe = DateTimeOffset.UtcNow;
                            _media?.Record("LocalProxyHealth", health);
                            _proxyHealthFailures = health.Ready ? 0 : _proxyHealthFailures + 1;
                            Event(health.Ready ? "LocalProxyHealthTcpUdpPassed" : "LocalProxyHealth_" + health.Failure);
                            if (_proxyHealthFailures >= 2) throw new IOException("PROXY_UPSTREAM_UNRESPONSIVE");
                        }
                        if (System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().Any(n => n.Name == "xray_tun" && n.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up)) throw new IOException("TUN_OTHER_TUN_APPEARED");
                    }
                    catch (Exception ex) { _apiFails++; _apiBudget.Failure(); _media?.Record("ApiOrSafetyLoopError", new { Failure = SafeCode(ex), ApiFailures = _apiFails }); if (ex.Message is "TUN_NON_GAME_NODE_ROUTE" or "TUN_COMPONENT_STOPPED" or "TUN_OTHER_TUN_APPEARED" or "PROXY_OWNER_CHANGED" or "V2RAY_EXITED" or "PROXY_LISTENER_GONE" or "PROXY_UPSTREAM_UNRESPONSIVE" or "PROXY_CONFIGURATION_CHANGED" || _apiBudget.MustStop) { _failure = SafeCode(ex); _termination = "ControllerSafetyFailure"; Event("ControllerSafetyStopRequested"); _ = Task.Run(StopAsync); break; } }
                    try { await Task.Delay(250, _pollCancel.Token); } catch (OperationCanceledException) { break; }
                }
            });
        }
        catch (Exception ex) { _failure = SafeCode(ex); _termination = _created ? "ControllerStartupFailure" : "PreflightBlockedNoCore"; Event("StartupRejected_" + _failure); await StopAsync(); throw new IOException(_failure); }
    }
    internal static bool V4Matches(string address, string? prefix)
        => prefix is not null && prefix.Contains('.') && PrefixMatches(address, prefix);
    internal static bool PrefixMatches(string address, string? prefix)
    {
        if (prefix is null || !prefix.Contains('/')) return false;
        var parts = prefix.Split('/'); var a = IPAddress.Parse(address).GetAddressBytes(); var n = IPAddress.Parse(parts[0]).GetAddressBytes();
        if (a.Length != n.Length || !int.TryParse(parts[1], out int length) || length < 0 || length > a.Length * 8) return false;
        for (int bit = 0; bit < length; bit++) if ((a[bit / 8] & (1 << (7 - bit % 8))) != (n[bit / 8] & (1 << (7 - bit % 8)))) return false;
        return true;
    }
    public static string SafeCode(Exception ex) => System.Text.RegularExpressions.Regex.IsMatch(ex.Message, "^[A-Z][A-Z0-9_]{2,89}$") ? ex.Message : "TUN_" + ex.GetType().Name.ToUpperInvariant();
    public static async Task CheckAsync(string config)
    {
        var psi = new ProcessStartInfo(AionTunPlan.CorePath) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string a in new[] { "check", "-c", config }) psi.ArgumentList.Add(a); using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEndAsync(); var stderr = p.StandardError.ReadToEndAsync();
        try { await p.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15)); } catch { p.Kill(); throw new IOException("TUN_CHECK_TIMEOUT"); }
        await stdout; await stderr; if (p.ExitCode != 0) throw new IOException("TUN_CORE_CHECK_REJECTED"); // Never export config-bearing stderr.
    }
    private async Task PollAsync()
    {
        var latency = Stopwatch.StartNew();
        using var response = await _api!.GetAsync("/connections"); response.EnsureSuccessStatusCode(); var bytes = await response.Content.ReadAsByteArrayAsync();
        if (bytes.Length > 512_000) throw new IOException("TUN_API_LIMIT"); var json = JsonNode.Parse(bytes)!; _polls++;
        foreach (var n in json["connections"]!.AsArray())
        {
            var m = n!["metadata"]!; string path = AionTunPlan.CanonicalProcess((string?)m["processPath"] ?? "");
            bool main = string.Equals(path, _main.ExecutablePath, StringComparison.OrdinalIgnoreCase);
            string inbound = (string?)m["type"] ?? ""; bool probe = _technical && inbound == "socks/node-check";
            var tags = n["chains"]!.AsArray().Select(x => (string?)x).ToArray(); string outbound = tags.Contains("v2ray-local") ? "v2ray-local" : tags.Contains("direct") ? "direct" : "unknown";
            if (tags.Contains("discord-media")) outbound = "discord-media";
            bool approvedDiscord = _discord.Any(p => string.Equals(p.Path, path, StringComparison.OrdinalIgnoreCase));
            bool discordProbe = _discord.Count > 0 && inbound == "socks/discord-check";
            if (outbound == "discord-media" && !discordProbe && (!approvedDiscord || (string?)m["network"] != "udp")) throw new IOException("TUN_NON_GAME_NODE_ROUTE");
            if (outbound == "v2ray-local" && !main && !probe) throw new IOException("TUN_NON_GAME_NODE_ROUTE");
            string id = AionTunPlan.Hash((string)n["id"]!); string file = Path.GetFileName(path);
            string? destination = (string?)m["destinationIP"]; string basis = "IpAddressHash";
            if (string.IsNullOrWhiteSpace(destination)) { destination = (string?)m["host"]; basis = string.IsNullOrWhiteSpace(destination) ? "Unknown" : "HostnameHash"; }
            if (!System.Text.RegularExpressions.Regex.IsMatch(file, @"\A[A-Za-z0-9_.-]{1,64}\z")) file = "Unknown";
            lock (_gate)
            {
                if (!_flows.ContainsKey(id) && _flows.Count >= 128)
                {
                    // Reserve evidence for the selected apps; unrelated xray churn must not hide the game/media.
                    if (main || approvedDiscord || discordProbe || probe)
                    { var victim = _flows.Values.Where(f => !f.SelectedMain && f.Component != "Discord.exe" && f.Component != "AuthenticatedProxyProbe" && f.Component != "DiscordUdpProbe").MinBy(f => f.LastObservedUtc) ?? _flows.Values.MinBy(f => f.LastObservedUtc); _flows.Remove(victim!.IdSha256); }
                    else { _historyDropped++; continue; }
                }
                var now = DateTimeOffset.UtcNow;
                _flows[id] = new(id, discordProbe ? "DiscordUdpProbe" : probe ? "AuthenticatedProxyProbe" : main ? "AION2.exe" : file, main,
                    AionTunPlan.Hash(string.IsNullOrWhiteSpace(destination) ? "unknown" : destination), (string?)m["network"] ?? "unknown",
                    int.TryParse((string?)m["destinationPort"], out var port) ? port : 0, outbound, _flows.TryGetValue(id, out var old) ? old.FirstObservedUtc : now, now,
                    (long?)n["upload"] ?? 0, (long?)n["download"] ?? 0, basis);
            }
        }
        if (_media is not null && DateTimeOffset.UtcNow - _lastMedia >= TimeSpan.FromSeconds(1))
        { _lastMedia = DateTimeOffset.UtcNow; _media.Sample(json["connections"]!.AsArray(), _discord, _main.ExecutablePath, _lastMedia, latency.Elapsed.TotalMilliseconds); }
        if (_media is not null && DateTimeOffset.UtcNow - _lastIdentity >= TimeSpan.FromSeconds(5))
        { _lastIdentity = DateTimeOffset.UtcNow; _media.Record("ProcessIdentityAndTcpSockets", DiscordMediaProfile.ProcessEvidence(_discord, _localProxy, (string?)_baseline?["Proxy"]?["Server"])); }
    }
    private async Task CheckDiscordUdpAsync()
    {
        _lastDiscordProbe = DateTimeOffset.UtcNow;
        try
        {
            var proof = await DiscordUdpProbe.RunAsync(_discordProbePort, _apiSecret, async () => { await PollAsync(); await Task.Delay(250); });
            if (!Evidence.Flows.Any(f => f.Component == "DiscordUdpProbe" && f.Outbound == "discord-media" && f.Network == "udp")) throw new IOException("DISCORD_UDP_API_ROUTE_NOT_OBSERVED");
            _discordUdpProof = proof; _discordWarning = null; _media?.Record("UdpChainProbe", proof);
        }
        catch (Exception ex)
        { _discordWarning = SafeCode(ex); _discordUdpProof = new { Passed = false, Utc = DateTimeOffset.UtcNow, Failure = _discordWarning }; _media?.Record("UdpChainProbeFailed", _discordUdpProof); }
        // Runtime diagnostic failure is visible but does not stop Aion, reset sockets, or switch Discord to direct.
    }
    private void VerifyListenerPresent()
    {
        bool v6 = IPAddress.Parse(_localProxy.Host).AddressFamily == AddressFamily.InterNetworkV6;
        if (!TcpOwnership.ReadBindings(v6).Any(b => b.ProcessId == _localProxy.OwnerPid && b.State == 2 && b.Flow.LocalPort == _localProxy.Port)) throw new IOException("PROXY_LISTENER_GONE");
    }
    private void ObserveLocalProxySocket()
    {
        if (_pid is null) return;
        bool v6 = IPAddress.Parse(_localProxy.Host).AddressFamily == AddressFamily.InterNetworkV6;
        var address = VakoLink.AntiDpi.Core.PacketAddress.Read(IPAddress.Parse(_localProxy.Host).GetAddressBytes(), v6);
        if (!_physicalSocket && TcpOwnership.ReadBindings(v6).Any(b => b.ProcessId == _pid && b.State == 5 && b.Flow.Remote == address && b.Flow.RemotePort == _localProxy.Port))
        { _physicalSocket = true; Event("CoreLocalProxyEstablished"); }
    }
    public async Task<JsonObject> TechnicalProbesAsync()
    {
        if (!_technical || !_running) throw new IOException("TUN_TECHNICAL_MODE_REQUIRED");
        // Raw TCP sentinel deliberately ignores the pre-existing system proxy; loopback SOCKS checks the copied outbound.
        using var direct = new TcpClient(); await direct.ConnectAsync("example.com", 80).WaitAsync(TimeSpan.FromSeconds(10));
        using var throughNode = new TcpClient(); await throughNode.ConnectAsync(IPAddress.Loopback, _probePort).WaitAsync(TimeSpan.FromSeconds(5)); var s = throughNode.GetStream();
        await s.WriteAsync(new byte[] { 5, 1, 2 }); var two = new byte[2]; await s.ReadExactlyAsync(two).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        if (two[1] != 2) throw new IOException("TUN_PROBE_AUTH_METHOD"); var user = Encoding.ASCII.GetBytes("probe"); var pass = Encoding.ASCII.GetBytes(_apiSecret);
        await s.WriteAsync(new byte[] { 1, (byte)user.Length }.Concat(user).Append((byte)pass.Length).Concat(pass).ToArray()); await s.ReadExactlyAsync(two).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        if (two[1] != 0) throw new IOException("TUN_PROBE_AUTH_FAILED"); var host = Encoding.ASCII.GetBytes("example.com");
        await s.WriteAsync(new byte[] { 5, 1, 0, 3, (byte)host.Length }.Concat(host).Concat(new byte[] { 0, 80 }).ToArray()); var header = new byte[4];
        await s.ReadExactlyAsync(header).AsTask().WaitAsync(TimeSpan.FromSeconds(12)); if (header[1] != 0) throw new IOException("TUN_NODE_CONNECT_FAILED");
        int addressBytes = header[3] == 1 ? 4 : header[3] == 4 ? 16 : 0; if (addressBytes == 0) throw new IOException("TUN_SOCKS_REPLY_FORMAT");
        await s.ReadExactlyAsync(new byte[addressBytes + 2]).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        var request = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n");
        await direct.GetStream().WriteAsync(request); await s.WriteAsync(request); var b = new byte[256];
        int directBytes = await direct.GetStream().ReadAsync(b).AsTask().WaitAsync(TimeSpan.FromSeconds(10)); int nodeBytes = await s.ReadAsync(b).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        for (int i = 0; i < 8; i++) { await PollAsync(); ObserveLocalProxySocket(); await Task.Delay(250); }
        bool nodeProof = Evidence.Flows.Any(f => f.Component == "AuthenticatedProxyProbe" && f.Outbound == "v2ray-local");
        string sentinel = Path.GetFileName(Environment.ProcessPath ?? throw new IOException("TUN_SENTINEL_IMAGE_UNKNOWN"));
        bool directProof = Evidence.Flows.Any(f => !f.SelectedMain && f.Component == sentinel && f.Port == 80 && f.Outbound == "direct");
        if (!nodeProof || !directProof || !_physicalSocket || directBytes <= 0 || nodeBytes <= 0) throw new IOException("TUN_ACTUAL_ROUTE_PROOF_INCOMPLETE");
        return new JsonObject
        {
            ["Passed"] = true,
            ["RawTcpSentinelDirectObserved"] = directProof,
            ["RawTcpSentinelComponent"] = sentinel,
            ["AuthenticatedProbeLocalProxyObserved"] = nodeProof,
            ["LocalProxyTcpResponse"] = nodeBytes > 0,
            ["CoreLocalProxySocketObserved"] = _physicalSocket,
            ["GameVerified"] = false,
            ["PayloadLogged"] = false
        };
    }
    public async Task<JsonObject> DiscordSustainedTechnicalAsync()
    {
        if (!_technical || !_running || _discord.Count == 0) throw new IOException("TUN_TECHNICAL_MODE_REQUIRED");
        var proof = await DiscordUdpProbe.RunAsync(_discordProbePort, _apiSecret, samples: 6, intervalMs: 15000);
        _media?.Record("SustainedUdpTechnicalProbe", proof); return proof;
    }
    public async Task StopAsync()
    {
        await _stop.WaitAsync();
        try
        {
            if (_clean && _child is null) return;
            _pollCancel?.Cancel();
            string polling = await ProxyStopBarrier.DrainAsync(_poller, 20000);
            string media = await ProxyStopBarrier.DrainAsync(_discordProbeTask, 15000);
            if (polling.Contains("CoreStop", StringComparison.Ordinal)) Event("StopPolling_" + polling);
            if (media.Contains("CoreStop", StringComparison.Ordinal)) Event("StopMediaProbe_" + media);
            if (_created && _child?.Process.HasExited == true) { _termination = "CoreSelfExitBeforeControllerStop"; Event("CoreAlreadyExited"); }
            if (_created && _termination == "NotStarted") _termination = "ControllerRequestedStop";
            Event("CleanupStarted");
            if (_child is not null)
            {
                await _child.StopAsync(); _graceful = _child.GracefulSignal; _forced = _child.Forced;
                _exited = _created && _child.Process.HasExited; if (_exited) _exitCode = _child.Process.ExitCode;
                _child.Dispose(); _child = null;
                _running = false;
                string stderr = Path.Combine(_operation!, "core-stderr.txt");
                if (File.Exists(stderr))
                {
                    using (var f = File.OpenRead(stderr))
                    {
                        _stderrTruncated = f.Length > 65536; var b = new byte[(int)Math.Min(65536, f.Length)]; f.ReadExactly(b); _stderrBytes = b.Length;
                        TunPrivateStore.WriteProtected(Path.Combine(_operation!, "core-stderr.dpapi"), new JsonObject { ["Bytes"] = Convert.ToBase64String(b), ["Truncated"] = _stderrTruncated }.ToJsonString()); CryptographicOperations.ZeroMemory(b);
                    }
                    File.Delete(stderr); _stderrStatus = _stderrBytes == 0 ? "Empty" : "PrivateDpapiOnly_NoRawReport";
                }
            }
            await Observer.StopAsync(); _api?.Dispose(); _api = null;
            if (_config is not null) { File.Delete(_config); _secretDeleted = !File.Exists(_config); } else _secretDeleted = true;
            if (_baseline is not null)
            {
                JsonObject? after = null;
                for (int i = 0; i < 3; i++)
                {
                    after = await SnapshotAsync(_networkScript); _comparison = Compare(_baseline, after);
                    _cleanupAssessment = _plan is null ? null : ProxyCleanupPolicy.Assess(_baseline, _during, after, _plan);
                    if (_cleanupAssessment is not null) lock (_gate)
                    {
                        if (_cleanupChecks.Count >= 32) _cleanupChecks.RemoveAt(0);
                        _cleanupChecks.Add(new(DateTimeOffset.UtcNow, _comparison, _cleanupAssessment, ProxyNetworkIsolation.DescribeChanges(_baseline, after)));
                    }
                    if (_cleanupAssessment?.SafeToReleaseJournal == true) break; await Task.Delay(800);
                }
                if (_operation is not null && after is not null) TunPrivateStore.WriteProtected(Path.Combine(_operation, "after.dpapi"), after.ToJsonString());
                _cleanupAssessment = _plan is null ? null : ProxyCleanupPolicy.Assess(_baseline, _during, after!, _plan);
                _clean = (!_created || _exited) && _secretDeleted && (!_created || _cleanupAssessment?.SafeToReleaseJournal == true) && Observer.Evidence.Native.RollbackCompleted
                    && (_poller is null || _poller.IsCompleted) && (_discordProbeTask is null || _discordProbeTask.IsCompleted);
            }
            else _clean = !_created && _secretDeleted && Observer.Evidence.Native.RollbackCompleted;
            bool resourcesVerified = _clean; _clean = false;
            if (resourcesVerified)
            {
                _marker?.Dispose(); _marker = null;
                if (_ownsMarker && File.Exists(ProxyJournal.MarkerPath))
                {
                    var ownMarker = JsonNode.Parse(await File.ReadAllTextAsync(ProxyJournal.MarkerPath))!;
                    if ((string?)ownMarker["Operation"] != Path.GetFileName(_operation)) throw new IOException("TUN_JOURNAL_OWNERSHIP_CHANGED");
                    File.Move(ProxyJournal.MarkerPath, Path.Combine(_operation!, "closed-marker-" + Guid.NewGuid().ToString("N") + ".json"));
                }
                _markerRemoved = !File.Exists(ProxyJournal.MarkerPath); _ownsMarker = false;
                _clean = true;
            }
            _coreLock?.Dispose(); _coreLock = null; _mainLock?.Dispose(); _mainLock = null; _running = false;
            foreach (var f in _discordLocks) f.Dispose(); _discordLocks.Clear(); _media?.Record("TransportStopped", new { _failure, _exitCode, Cleanup = _clean, BaselineAfter = _comparison });
            // Never delete/restore physical-interface routes/DNS or unrelated Windows state to conceal a mismatch.
            if (!_clean) _failure ??= _cleanupAssessment?.Blockers.FirstOrDefault() ?? "TUN_BASELINE_AFTER_MISMATCH";
            if (_baseline is not null) _failure = ProxyNetworkIsolation.FinalFailure(_failure, _clean);
            if (_clean) { _lease?.Dispose(); _lease = null; }
            Event(!_created && _baseline is null ? "AttemptAbortedNoOwnedCore" : !_clean ? "CleanupNotConfirmed" :
                _comparison.Values.All(v => v) ? "CleanupConfirmed" : "CleanupOwnedResourcesConfirmed_ExternalStateChanged");
        }
        finally { _stop.Release(); }
    }
    public async ValueTask DisposeAsync() => await StopAsync();
}
