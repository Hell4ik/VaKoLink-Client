using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using System.Security.Cryptography;
using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public sealed record TunFlowEvidence(string IdSha256, string Component, bool SelectedMain, string DestinationSha256, string Network, int Port,
    string Outbound, DateTimeOffset FirstObservedUtc, DateTimeOffset LastObservedUtc, long Upload, long Download, string DestinationBasis = "IpAddressOrHostnameHash");
public sealed record TunLifecycleEvent(string Stage, DateTimeOffset Utc, long ElapsedMs);
public sealed record TunSessionEvidence(string Core, string CoreVersion, string CoreSha256, bool Running, int? CoreProcessId, string? Failure,
    bool GeneralTunCapture, bool OwnAntiDpiActive, bool PhysicalBindingConfigured, bool NodeRouteExcluded, bool CoreNodePhysicalSocketObserved,
    bool NativeDnsDisabled, bool ExistingSystemProxyPreserved, bool TechnicalProbeMode, bool GracefulSignal, bool ForcedTermination,
    bool CoreExited, bool SecretConfigurationDeleted, bool MarkerRemoved, bool CleanupConfirmed, IReadOnlyDictionary<string, bool> BaselineAfter,
    IReadOnlyList<TunFlowEvidence> Flows, int ApiPolls, int ApiFailures, int HistoryDropped,
    bool CoreCreated = false, int? CoreExitCode = null, string TerminationInitiator = "NotStarted", string CleanupBasis = "NotChecked",
    AionTunPlan.PinEvidence? FilePins = null, IReadOnlyList<TunLifecycleEvent>? Lifecycle = null,
    string StderrStatus = "NotStarted", int StderrCapturedBytes = 0, bool StderrTruncated = false,
    string Coverage = "Bounded 250ms active connection snapshots; short/closed-between-polls flows can be missed. TUN ACK is client-facing TCP termination, not game receiver acceptance. Unknown owners final=direct; DNS direct even for game; existing explicit HTTP/SOCKS proxies are NOT overridden.");

public sealed class AionTunSession : IAsyncDisposable
{
    private readonly JsonObject _capsule; private readonly AppProfile _main; private readonly object _gate = new();
    private readonly SemaphoreSlim _stop = new(1, 1); private readonly Dictionary<string, TunFlowEvidence> _flows = new();
    private readonly string _engine, _networkScript; private readonly bool _technical;
    private readonly bool _observe; private IDisposable? _lease; private readonly ApiFailureBudget _apiBudget = new();
    private TunChildProcess? _child; private FileStream? _coreLock, _mainLock, _marker;
    private HttpClient? _api; private Task? _poller; private CancellationTokenSource? _pollCancel; private JsonObject? _baseline;
    private string? _operation, _config, _failure; private bool _running, _excluded, _physicalSocket, _proxy, _clean, _secretDeleted, _markerRemoved;
    private bool _graceful, _forced, _exited; private int _apiPort, _probePort, _polls, _apiFails, _historyDropped; private string _apiSecret = "";
    private int? _pid; private IReadOnlyDictionary<string, bool> _comparison = new Dictionary<string, bool>();
    private readonly Stopwatch _lifecycleClock = Stopwatch.StartNew(); private readonly List<TunLifecycleEvent> _events = [];
    private AionTunPlan.PinEvidence? _pins; private bool _created; private int? _exitCode;
    private string _termination = "NotStarted", _stderrStatus = "NotStarted"; private int _stderrBytes; private bool _stderrTruncated;
    private void Event(string stage) { lock (_gate) _events.Add(new(stage, DateTimeOffset.UtcNow, _lifecycleClock.ElapsedMilliseconds)); }
    public string? ConfigurationSha256 { get; private set; }
    public GamePassiveTrace Observer { get; }
    public AionTunSession(JsonObject capsule, IReadOnlyList<AppProfile> profiles, string engine, string networkScript, bool technical = false, bool observe = false)
    {
        _capsule = capsule; _main = profiles[0]; _engine = engine; _networkScript = networkScript; _technical = technical; _observe = observe;
        Observer = new(profiles, detailedAion: true, postCloseTail: true);
    }
    public TunSessionEvidence Evidence
    {
        get
        {
            lock (_gate) return new("sing-box (third-party transport, NOT direct AntiDPI)", AionTunPlan.CoreVersion,
        AionTunPlan.CoreSha256, _running, _pid, _failure, true, false, _baseline is not null, _excluded, _physicalSocket, true, _proxy, _technical,
        _graceful, _forced, _exited, _secretDeleted, _markerRemoved, _clean, new Dictionary<string, bool>(_comparison), _flows.Values.ToArray(), _polls, _apiFails, _historyDropped,
        _created, _exitCode, _termination, _baseline is null ? "NoNativeMutationAttempted" : "EightSnapshotCategoriesAndObserverRollback",
        _pins, _events.ToArray(), _stderrStatus, _stderrBytes, _stderrTruncated);
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
        if (p.ExitCode != 0 || json.Length > 1_000_000) throw new IOException("TUN_SNAPSHOT_FAILED"); return JsonNode.Parse(json)!.AsObject();
    }
    public static IReadOnlyDictionary<string, bool> Compare(JsonObject before, JsonObject after) => new[] { "Adapters", "Routes", "Addresses", "Interfaces", "DNS", "Firewall", "Proxy", "SourceRuntimeSHA" }
        .ToDictionary(k => k, k => JsonNode.DeepEquals(before[k], after[k]));
    public static async Task<JsonObject> RecoverJournalAsync(string script)
    {
        string marker = Path.Combine(TunPrivateStore.Root, "active-operation.json"); var m = JsonNode.Parse(await File.ReadAllTextAsync(marker))!;
        string operation = (string)m["Operation"]!; if (!Guid.TryParseExact(operation, "N", out _)) throw new IOException("TUN_RECOVERY_JOURNAL_INVALID");
        int pid = (int)m["ParentPid"]!;
        try { using var parent = Process.GetProcessById(pid); if (parent.StartTime.ToUniversalTime() == DateTime.Parse((string)m["ParentBirthUtc"]!, null, System.Globalization.DateTimeStyles.RoundtripKind).ToUniversalTime()) throw new IOException("TUN_OWNER_STILL_ALIVE_STOP_IN_WINDOW"); }
        catch (ArgumentException) { }
        if (Process.GetProcessesByName("sing-box").Length != 0) throw new IOException("TUN_RECOVERY_CORE_STILL_PRESENT");
        string folder = Path.Combine(TunPrivateStore.Root, operation); TunPrivateStore.EnsurePrivate(folder);
        var before = TunPrivateStore.ReadProtected(Path.Combine(folder, "baseline.dpapi")); var after = await SnapshotAsync(script); var compare = Compare(before, after);
        TunPrivateStore.WriteProtected(Path.Combine(folder, "recovery-after.dpapi"), after.ToJsonString());
        if (!compare.Values.All(x => x)) throw new IOException("TUN_RECOVERY_BASELINE_MISMATCH");
        File.Delete(Path.Combine(folder, "run-config.json")); File.Delete(marker);
        return new JsonObject
        {
            ["Recovered"] = true,
            ["Operation"] = operation,
            ["CoreAbsent"] = true,
            ["AdapterRoutesDnsRestored"] = true,
            ["BaselineAfter"] = System.Text.Json.JsonSerializer.SerializeToNode(compare),
            ["OnlyOwnedPlainConfigAndMarkerDeleted"] = true,
            ["NetworkMutationCommandsUsed"] = false
        };
    }
    public async Task StartAsync()
    {
        try
        {
            Event("PreflightStarted");
            if (!RuntimePreflight.IsAdministrator() || RuntimePreflight.GetConflicts().Count != 0 || Process.GetProcessesByName("sing-box").Length != 0
                || Process.GetProcessesByName("AION2").Length != 0) throw new IOException("TUN_PREFLIGHT_CONFLICT");
            TunPrivateStore.VerifyImagePath(_main.ExecutablePath); TunPrivateStore.VerifyImagePath(AionTunPlan.CorePath);
            string expectedMain = (string?)_capsule["MainSHA256"] ?? "";
            _pins = new(AionTunPlan.CoreSha256, AionTunPlan.FileHash(AionTunPlan.CorePath), expectedMain,
                AionTunPlan.FileHash(_main.ExecutablePath), GameComponentTrust.IsSignedNcImage(_main.ExecutablePath),
                string.Equals((string?)_capsule["MainPath"], _main.ExecutablePath, StringComparison.OrdinalIgnoreCase),
                (string?)_capsule["CoreSHA256"] == AionTunPlan.CoreSha256 && System.Text.RegularExpressions.Regex.IsMatch(expectedMain, "^[A-F0-9]{64}$"));
            if (AionTunPlan.PinFailure(_pins) is { } failure) throw new IOException(failure);
            Event("FilePinsAndSignatureVerified");
            TunPrivateStore.EnsurePrivate(TunPrivateStore.Root);
            string markerPath = Path.Combine(TunPrivateStore.Root, "active-operation.json");
            if (File.Exists(markerPath)) throw new IOException("TUN_PREVIOUS_OPERATION_REQUIRES_RECOVERY");
            _baseline = await SnapshotAsync(_networkScript);
            Event("BaselineCaptured");
            if ((bool?)_baseline["V2rayTunEnabled"] == true || (bool?)_baseline["Physical"]?["Hardware"] != true
                || _baseline["Adapters"]!.AsArray().Any(a => (string?)a?["Name"] == AionTunPlan.AdapterName || (string?)a?["Name"] == "xray_tun")
                || _baseline["Routes"]!.AsArray().Any(r => (string?)r?["DestinationPrefix"] is "0.0.0.0/1" or "128.0.0.0/1" or "::/1" or "8000::/1")) throw new IOException("TUN_EXISTING_TUN_OR_DEFAULT_NOT_PHYSICAL");
            if (_baseline["Addresses"]!.AsArray().Any(a => PrefixMatches((string)a!["IPAddress"]!, "172.29.219.0/30") || PrefixMatches((string)a["IPAddress"]!, "fd94:61e9:7b13::/126"))) throw new IOException("TUN_PRIVATE_ADDRESS_COLLISION");
            _proxy = (int?)_baseline["Proxy"]?["Enable"] == 1;
            string physical = (string)_baseline["Physical"]!["Name"]!;
            _coreLock = new(AionTunPlan.CorePath, FileMode.Open, FileAccess.Read, FileShare.Read); _mainLock = new(_main.ExecutablePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (AionTunPlan.FileHash(AionTunPlan.CorePath) != AionTunPlan.CoreSha256 || AionTunPlan.FileHash(_main.ExecutablePath) != expectedMain) throw new IOException("TUN_LOCKED_IMAGE_CHANGED");
            if (!_observe) _lease = new SessionDependencies().AcquireLease();
            _operation = Path.Combine(TunPrivateStore.Root, Guid.NewGuid().ToString("N")); TunPrivateStore.EnsurePrivate(_operation);
            TunPrivateStore.WriteProtected(Path.Combine(_operation, "baseline.dpapi"), _baseline.ToJsonString());
            _marker = new(markerPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read); var markerBytes = Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(new { Operation = Path.GetFileName(_operation), ParentPid = Environment.ProcessId, ParentBirthUtc = Process.GetCurrentProcess().StartTime.ToUniversalTime(), StartedUtc = DateTimeOffset.UtcNow }));
            _marker.Write(markerBytes); _marker.Flush(true);
            _apiPort = FreePort(); _probePort = _technical ? FreePort() : 0; _apiSecret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            var config = AionTunPlan.Build(_capsule["Node"]!.AsObject(), _main.ExecutablePath, physical, _apiPort, _apiSecret, _probePort);
            _config = Path.Combine(_operation, "run-config.json"); await File.WriteAllTextAsync(_config, config.ToJsonString()); ConfigurationSha256 = AionTunPlan.FileHash(_config);
            TunPrivateStore.WriteProtected(Path.Combine(_operation, "configuration.dpapi"), config.ToJsonString());
            await CheckAsync(_config);
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
            var active = await SnapshotAsync(_networkScript);
            var own = active["Adapters"]!.AsArray().Where(a => (string?)a?["Name"] == AionTunPlan.AdapterName).ToArray();
            if (own.Length != 1) throw new IOException("TUN_ADAPTER_NOT_UNIQUE"); int ownIndex = (int)own[0]!["InterfaceIndex"]!;
            Event("TunAdapterObserved");
            string nodeIP = (string)_capsule["Node"]!["server"]!;
            var ownRoutes = active["Routes"]!.AsArray().Where(r => (int?)r?["InterfaceIndex"] == ownIndex).ToArray();
            if (ownRoutes.Length == 0 || !ownRoutes.Any(r => PrefixMatches("2606:4700::1111", (string?)r?["DestinationPrefix"]))
                || !ownRoutes.Any(r => PrefixMatches("1.1.1.1", (string?)r?["DestinationPrefix"]))) throw new IOException("TUN_ROUTES_NOT_OBSERVED");
            _excluded = !ownRoutes.Any(r => V4Matches(nodeIP, (string?)r?["DestinationPrefix"]));
            if (!_excluded || !Unaffected(_baseline, active, ownIndex, "DNS") || !Unaffected(_baseline, active, ownIndex, "Interfaces")
                || !JsonNode.DeepEquals(_baseline["Proxy"], active["Proxy"]) || !JsonNode.DeepEquals(_baseline["Firewall"], active["Firewall"])) throw new IOException("TUN_ROUTING_DNS_ISOLATION_FAILED");
            _proxy = true;
            TunPrivateStore.WriteProtected(Path.Combine(_operation, "during.dpapi"), active.ToJsonString());
            _running = true; Event("TransportReadyForGame"); _pollCancel = new(); _poller = Task.Run(async () =>
            {
                while (!_pollCancel.IsCancellationRequested)
                {
                    try
                    {
                        await PollAsync(); _apiBudget.Success(); ObservePhysicalNodeSocket(); if ((_observe && !Observer.Evidence.Running) || _child.Process.HasExited) throw new IOException("TUN_COMPONENT_STOPPED");
                        if (System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().Any(n => n.Name == "xray_tun" && n.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up)) throw new IOException("TUN_OTHER_TUN_APPEARED");
                    }
                    catch (Exception ex) { _apiFails++; _apiBudget.Failure(); if (ex.Message is "TUN_NON_GAME_NODE_ROUTE" or "TUN_COMPONENT_STOPPED" or "TUN_OTHER_TUN_APPEARED" || _apiBudget.MustStop) { _failure = SafeCode(ex); _termination = "ControllerSafetyFailure"; Event("ControllerSafetyStopRequested"); _ = Task.Run(StopAsync); break; } }
                    try { await Task.Delay(250, _pollCancel.Token); } catch (OperationCanceledException) { break; }
                }
            });
        }
        catch (Exception ex) { _failure = SafeCode(ex); _termination = _created ? "ControllerStartupFailure" : "PreflightBlockedNoCore"; Event("StartupRejected_" + _failure); await StopAsync(); throw new IOException(_failure); }
    }
    private static bool Unaffected(JsonObject before, JsonObject after, int own, string key)
    { var b = new JsonArray(before[key]!.AsArray().Where(n => (int?)n?["InterfaceIndex"] != own).Select(n => n!.DeepClone()).ToArray()); var a = new JsonArray(after[key]!.AsArray().Where(n => (int?)n?["InterfaceIndex"] != own).Select(n => n!.DeepClone()).ToArray()); return JsonNode.DeepEquals(b, a); }
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
    public static string SafeCode(Exception ex) => System.Text.RegularExpressions.Regex.IsMatch(ex.Message, "^[A-Z_]{3,90}$") ? ex.Message : "TUN_" + ex.GetType().Name.ToUpperInvariant();
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
        using var response = await _api!.GetAsync("/connections"); response.EnsureSuccessStatusCode(); var bytes = await response.Content.ReadAsByteArrayAsync();
        if (bytes.Length > 512_000) throw new IOException("TUN_API_LIMIT"); var json = JsonNode.Parse(bytes)!; _polls++;
        foreach (var n in json["connections"]!.AsArray())
        {
            var m = n!["metadata"]!; string path = AionTunPlan.CanonicalProcess((string?)m["processPath"] ?? "");
            bool main = string.Equals(path, _main.ExecutablePath, StringComparison.OrdinalIgnoreCase);
            string inbound = (string?)m["type"] ?? ""; bool probe = _technical && inbound == "socks/node-check";
            var tags = n["chains"]!.AsArray().Select(x => (string?)x).ToArray(); string outbound = tags.Contains("germany") ? "germany" : tags.Contains("direct") ? "direct" : "unknown";
            if (outbound == "germany" && !main && !probe) throw new IOException("TUN_NON_GAME_NODE_ROUTE");
            string id = AionTunPlan.Hash((string)n["id"]!); string file = Path.GetFileName(path);
            string? destination = (string?)m["destinationIP"]; string basis = "IpAddressHash";
            if (string.IsNullOrWhiteSpace(destination)) { destination = (string?)m["host"]; basis = string.IsNullOrWhiteSpace(destination) ? "Unknown" : "HostnameHash"; }
            if (!System.Text.RegularExpressions.Regex.IsMatch(file, @"\A[A-Za-z0-9_.-]{1,64}\z")) file = "Unknown";
            lock (_gate)
            {
                if (!_flows.ContainsKey(id) && _flows.Count >= 128) { _historyDropped++; continue; }
                var now = DateTimeOffset.UtcNow;
                _flows[id] = new(id, probe ? "AuthenticatedNodeProbe" : main ? "AION2.exe" : file, main,
                    AionTunPlan.Hash(string.IsNullOrWhiteSpace(destination) ? "unknown" : destination), (string?)m["network"] ?? "unknown",
                    int.TryParse((string?)m["destinationPort"], out var port) ? port : 0, outbound, _flows.TryGetValue(id, out var old) ? old.FirstObservedUtc : now, now,
                    (long?)n["upload"] ?? 0, (long?)n["download"] ?? 0, basis);
            }
        }
    }
    private void ObservePhysicalNodeSocket()
    {
        if (_baseline is null || _pid is null) return;
        var node = IPAddress.Parse((string)_capsule["Node"]!["server"]!).GetAddressBytes(); uint remote = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(node);
        var locals = _baseline["Addresses"]!.AsArray().Where(a => (int?)a?["InterfaceIndex"] == (int?)_baseline["Physical"]?["Index"] && ((string?)a?["IPAddress"])?.Contains('.') == true)
            .Select(a => System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(IPAddress.Parse((string)a!["IPAddress"]!).GetAddressBytes())).ToArray();
        if (!_physicalSocket && TcpOwnership.ReadBindings(false).Any(b => b.ProcessId == _pid && b.State == 5 && !b.Flow.Remote.V6 && b.Flow.Remote.A == remote && locals.Contains(b.Flow.Local.A))) { _physicalSocket = true; Event("CoreNodeEstablishedOnPhysicalInterface"); }
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
        for (int i = 0; i < 8; i++) { await PollAsync(); ObservePhysicalNodeSocket(); await Task.Delay(250); }
        bool nodeProof = Evidence.Flows.Any(f => f.Component == "AuthenticatedNodeProbe" && f.Outbound == "germany");
        string sentinel = Path.GetFileName(Environment.ProcessPath ?? throw new IOException("TUN_SENTINEL_IMAGE_UNKNOWN"));
        bool directProof = Evidence.Flows.Any(f => !f.SelectedMain && f.Component == sentinel && f.Port == 80 && f.Outbound == "direct");
        if (!nodeProof || !directProof || !_physicalSocket || directBytes <= 0 || nodeBytes <= 0) throw new IOException("TUN_ACTUAL_ROUTE_PROOF_INCOMPLETE");
        return new JsonObject
        {
            ["Passed"] = true,
            ["RawTcpSentinelDirectObserved"] = directProof,
            ["RawTcpSentinelComponent"] = sentinel,
            ["AuthenticatedProbeGermanyObserved"] = nodeProof,
            ["CopiedNodeTcpResponse"] = nodeBytes > 0,
            ["PhysicalCoreNodeSocketObserved"] = _physicalSocket,
            ["GameVerified"] = false,
            ["PayloadLogged"] = false
        };
    }
    public async Task StopAsync()
    {
        await _stop.WaitAsync();
        try
        {
            if (_clean && _child is null) return;
            _pollCancel?.Cancel(); if (_poller is not null) await _poller.WaitAsync(TimeSpan.FromSeconds(5));
            if (_created && _child?.Process.HasExited == true) { _termination = "CoreSelfExitBeforeControllerStop"; Event("CoreAlreadyExited"); }
            if (_created && _termination == "NotStarted") _termination = "ControllerRequestedStop";
            Event("CleanupStarted");
            if (_child is not null)
            {
                await _child.StopAsync(); _graceful = _child.GracefulSignal; _forced = _child.Forced;
                _exited = _created && _child.Process.HasExited; if (_exited) _exitCode = _child.Process.ExitCode;
                _child.Dispose(); _child = null;
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
                for (int i = 0; i < 3; i++) { after = await SnapshotAsync(_networkScript); _comparison = Compare(_baseline, after); if (_comparison.Values.All(v => v)) break; await Task.Delay(800); }
                if (_operation is not null && after is not null) TunPrivateStore.WriteProtected(Path.Combine(_operation, "after.dpapi"), after.ToJsonString());
                _clean = (!_created || _exited) && _secretDeleted && _comparison.Values.All(v => v) && Observer.Evidence.Native.RollbackCompleted;
            }
            else _clean = !_created && _secretDeleted && Observer.Evidence.Native.RollbackCompleted;
            if (_clean) { _marker?.Dispose(); _marker = null; string m = Path.Combine(TunPrivateStore.Root, "active-operation.json"); if (_operation is not null) File.Delete(m); _markerRemoved = !File.Exists(m); _clean = _markerRemoved; }
            _coreLock?.Dispose(); _coreLock = null; _mainLock?.Dispose(); _mainLock = null; _running = false;
            // Never delete/restore physical-interface routes/DNS or unrelated Windows state to conceal a mismatch.
            if (!_clean) _failure ??= "TUN_BASELINE_AFTER_MISMATCH";
            if (_clean) { _lease?.Dispose(); _lease = null; }
            Event(_clean ? "CleanupConfirmed" : "CleanupNotConfirmed");
        }
        finally { _stop.Release(); }
    }
    public async ValueTask DisposeAsync() => await StopAsync();
}
