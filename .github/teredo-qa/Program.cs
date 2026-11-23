using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using VakoLink.AntiDpi.Windows;

internal static class Program
{
    private static readonly string SnapshotScript = Path.Combine(AppContext.BaseDirectory, "tools", "ProxyNetworkState.ps1");
    private static readonly string DiscoveryScript = Path.Combine(AppContext.BaseDirectory, "tools", "Discover-LocalProxy.ps1");
    private static readonly JsonSerializerOptions ReportOptions = new() { WriteIndented = true };
    private static readonly string[] StateCategories = ["Adapters", "Addresses", "Routes", "Interfaces", "DNS"];

    [STAThread]
    private static int Main(string[] args)
    {
        if (args is ["--probe-local-v6", var tcpPort, var udpPort])
            return RoutedDiagnosticProbe.TestIpv6LoopbackAsync(int.Parse(tcpPort), int.Parse(udpPort)).GetAwaiter().GetResult();
        if (args is ["--probe-routed-v4", var address, var index, var directory])
            return RoutedDiagnosticProbe.RequestAsync(address, int.Parse(index), directory).GetAwaiter().GetResult();
        if (args is ["--check"])
            return CheckInstalledFilesAsync().GetAwaiter().GetResult();
        if (args is ["--local-route-check"])
            return CheckLocalRouteAsync().GetAwaiter().GetResult();
        ApplicationConfiguration.Initialize();
        using var form = new Form { Text = "VaKoLink · Проверка IPv4-маршрутизации", Width = 590, Height = 260,
            StartPosition = FormStartPosition.CenterScreen, MaximizeBox = false };
        var text = new Label { Dock = DockStyle.Fill, Padding = new Padding(20), AutoSize = false,
            Text = "Оставьте VaKoLink v1.30 подключённым в Proxy. Выключите только «Маршрутизацию» и не запускайте её во время замера.\n\nПомощник проверит маршрутизацию своего тестового приложения и сохранит отчёт." };
        var button = new Button { Text = "Начать проверку", Dock = DockStyle.Bottom, Height = 44 };
        form.Controls.Add(text);
        form.Controls.Add(button);
        bool running = false;
        form.FormClosing += (_, eventArgs) => eventArgs.Cancel = running;
        button.Click += async (_, _) =>
        {
            running = true;
            button.Enabled = false;
            var progress = new Progress<string>(message => text.Text = message);
            try
            {
                var file = await Task.Run(() => Run(progress));
                text.Text = "Отчёт сохранён на рабочем столе. Передайте этот файл разработчику.\n\n" + Path.GetFileName(file);
            }
            catch (Exception error)
            {
                text.Text = "Не удалось записать отчёт. Код: " + ProxyTunSession.SafeCode(error);
            }
            finally { running = false; }
        };
        Application.Run(form);
        return 0;
    }

    private static string Run(IProgress<string> progress)
    {
        using var mutex = new Mutex(false, @"Local\VaKoLink-Teredo-Check-v130");
        // The mutex is acquired and released on this thread, outside asynchronous continuations.
        bool owned;
        try { owned = mutex.WaitOne(0); }
        catch (AbandonedMutexException) { owned = true; }
        if (!owned) throw new IOException("DIAGNOSTIC_ALREADY_RUNNING");
        try { return CaptureAsync(progress).GetAwaiter().GetResult(); }
        finally { mutex.ReleaseMutex(); }
    }

    private static async Task<string> CaptureAsync(IProgress<string> progress)
    {
        var report = new DiagnosticReport { StartedUtc = DateTimeOffset.UtcNow };
        try
        {
            progress.Report("Проверяем рабочий Proxy и исходное состояние Teredo…");
            using var core = OpenVerifiedCore();
            var initial = await StableSnapshotAsync();
            var proxy = await FindProxyAsync(initial);
            report.ProxyBefore = await ProbeAsync(proxy);
            var reference = await StableSnapshotAsync();
            var teredo = Rows(reference, "NativeInterfaces").Where(row => (int?)row["Type"] == 131
                && (int?)row["TunnelType"] == 14 && (bool?)row["Hardware"] == false
                && HasDefault(reference, (int)row["InterfaceIndex"]!)).ToArray();
            if (teredo.Length != 1) throw new IOException("TEREDO_DEFAULT_BASELINE_NOT_FOUND");
            int index = (int)teredo[0]["InterfaceIndex"]!;
            string identity = (string?)teredo[0]["Guid"] ?? "";
            if (!Guid.TryParse(identity, out Guid guid) || guid == Guid.Empty)
                throw new IOException("TEREDO_IDENTITY_UNAVAILABLE");
            progress.Report("Проверяем ограничение IPv6 для тестового приложения и запускаем адаптер IPv4…");
            report.Trial = new Trial();
            await RunTrialAsync(report.Trial, proxy, reference, index, identity);
        }
        catch (Exception error) { report.Blocker = ProxyTunSession.SafeCode(error); }

        report.CompletedUtc = DateTimeOffset.UtcNow;
        string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        string file = Path.Combine(desktop, $"VaKoLink-Teredo-Routed-{DateTime.Now:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.json");
        await using var output = new FileStream(file, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        await JsonSerializer.SerializeAsync(output, report, ReportOptions);
        return file;
    }

    private static FileStream OpenVerifiedCore()
    {
        TunPrivateStore.VerifyImagePath(AionTunPlan.CorePath);
        var core = new FileStream(AionTunPlan.CorePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (Convert.ToHexString(SHA256.HashData(core)) == AionTunPlan.CoreSha256) return core;
        core.Dispose();
        throw new IOException("TUN_CORE_HASH_CHANGED");
    }

    private static async Task<LocalProxyEndpoint> FindProxyAsync(JsonObject snapshot)
    {
        var proxy = snapshot["Proxy"];
        string server = (string?)proxy?["Server"] ?? "";
        if ((int?)proxy?["Enable"] != 1) throw new IOException("SYSTEM_PROXY_NOT_ENABLED");
        int[] ports = Regex.Matches(server, @"(?:^|=|;)(?:127\.0\.0\.1|localhost|\[::1\]):(\d+)(?=;|$)",
            RegexOptions.IgnoreCase).Select(match => int.Parse(match.Groups[1].Value)).Distinct().ToArray();
        var clients = (await LocalProxy.DiscoverAsync(DiscoveryScript)).Where(p => ports.Contains(p.Port)
            && p.Members.Any(member => member.Pid == p.GuiPid && IsClient130(member.Path))).ToArray();
        if (clients.Select(p => p.GuiPid).Distinct().Count() != 1)
            throw new IOException("ACTIVE_VAKOLINK_130_PROXY_NOT_UNIQUE");
        foreach (var candidate in clients)
        {
            if ((await ProbeAsync(candidate)).Ready) return candidate;
        }
        throw new IOException("PROXY_TCP_UDP_NOT_READY");
    }

    private static bool IsClient130(string path)
    {
        var version = FileVersionInfo.GetVersionInfo(path);
        return Path.GetFileName(path).Equals("VaKoLink.exe", StringComparison.OrdinalIgnoreCase)
            && version.FileMajorPart == 1 && version.FileMinorPart == 30;
    }

    private static async Task<SafeProbe> ProbeAsync(LocalProxyEndpoint proxy)
    {
        proxy.VerifyAlive();
        var result = await LocalProxy.ProbeAsync(proxy);
        return new(result.Ready, result.Socks5, result.TcpResponse, result.UdpResponse, result.DurationMs);
    }

    private static Task<JsonObject> StableSnapshotAsync() =>
        ProxyBaselineStability.CaptureAsync(() => ProxyTunSession.SnapshotAsync(SnapshotScript), _ => { });

    private static async Task RunTrialAsync(Trial trial, LocalProxyEndpoint proxy, JsonObject baseline, int index, string identity, bool isolatedFixture = false)
    {
        trial.Samples.Add(Sample("baseline", baseline, baseline, index, identity));
        int? ownedIndex = null;
        string? address = null;
        bool coreExited = false;
        try
        {
            VerifyNoConflicts(baseline, proxy, isolatedFixture);
            proxy.VerifyAlive();
            address = ProxyTunPlan.ChooseAddress(baseline);
            string operation = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "VaKoLink-Teredo-Check", Guid.NewGuid().ToString("N"));
            TunPrivateStore.EnsurePrivate(operation);
            try
            {
                string config = Path.Combine(operation, "probe.json");
                string probe = CopyProbe(operation);
                using var protection = new ApplicationIpv6Guard([probe]);
                trial.Ipv6GuardActive = true;
                int blocked = await RoutedDiagnosticProbe.TestLocalFilterAsync(probe);
                trial.Ipv6TcpBlocked = blocked is 1 or 3;
                trial.Ipv6UdpBlocked = blocked is 2 or 3;
                if (blocked != 3) throw new IOException("DIAGNOSTIC_IPV6_GUARD_NOT_VERIFIED");
                int api = FreePort();
                string secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
                var plan = BuildPlan(proxy, (string)baseline["Physical"]!["Name"]!,
                    (string)baseline["LoopbackInterface"]!, address, api, secret, probe);
                await File.WriteAllTextAsync(config, plan.ToJsonString());
                await ProxyTunSession.CheckAsync(config);
                using var child = new TunChildProcess();
                try
                {
                    trial.CoreStartUtc = DateTimeOffset.UtcNow;
                    child.Start(config);
                    for (int sample = 1; sample <= 3; sample++)
                    {
                        if (child.Process.HasExited) throw new IOException("DIAGNOSTIC_CORE_EXITED");
                        var active = await ProxyTunSession.SnapshotAsync(SnapshotScript);
                        trial.Samples.Add(Sample($"active-{sample}", baseline, active, index, identity));
                        var own = Rows(active, "Adapters").Where(row =>
                            (string?)row["Name"] == ProxyTunPlan.AdapterName && (bool?)row["HardwareInterface"] == false).ToArray();
                        if (own.Length != 1)
                        {
                            if (sample == 3) throw new IOException("DIAGNOSTIC_ADAPTER_NOT_OBSERVED");
                            continue;
                        }
                        ownedIndex = (int)own[0]["InterfaceIndex"]!;
                        trial.AdapterObserved = true;
                        trial.OwnIpv6AddressRows.Add(Rows(active, "Addresses").Count(row =>
                            (int?)row["InterfaceIndex"] == ownedIndex && (int?)row["AddressFamily"] == 23));
                        var audit = ProxyNetworkIsolation.Evaluate(baseline, active, ownedIndex.Value, proxy.Host, sample, 0);
                        trial.Audit.Add(new(sample, audit.Passed, audit.FailureCode, audit.InterfaceReports ?? []));
                        proxy.VerifyAlive();
                        if (!audit.Passed && !ProxyNetworkIsolation.CanRecheck(audit)) break;
                        await Task.Delay(500);
                    }
                    if (ownedIndex is int tunnelIndex && trial.Audit.LastOrDefault()?.Passed == true)
                    {
                        proxy.VerifyAlive();
                        var result = await RoutedDiagnosticProbe.RunAsync(probe, operation, tunnelIndex, address.Split('/')[0], api, secret);
                        trial.SocksChainObserved = result.ChainSeen;
                        trial.ProbeExitCode = result.ExitCode;
                        trial.HttpsPassed = result.ChainSeen && result.ExitCode == 0;
                        proxy.VerifyAlive();
                        var postTraffic = await ProxyTunSession.SnapshotAsync(SnapshotScript);
                        trial.Samples.Add(Sample("after-https", baseline, postTraffic, index, identity));
                        var lastAudit = ProxyNetworkIsolation.Evaluate(baseline, postTraffic, tunnelIndex, proxy.Host, 4, 0);
                        trial.Audit.Add(new(4, lastAudit.Passed, lastAudit.FailureCode, lastAudit.InterfaceReports ?? []));
                    }
                }
                finally
                {
                    await child.StopAsync();
                    coreExited = child.Process is null || child.Process.HasExited;
                    trial.CoreStopUtc = DateTimeOffset.UtcNow;
                }
                protection.Dispose();
                trial.Ipv6GuardRemoved = await RoutedDiagnosticProbe.TestLocalFilterAsync(probe, runWithoutFilter: true) == 0;
            }
            finally
            {
                foreach (string file in new[] { "probe.json", "core-stderr.txt", "ready", "confirmed", "VaKoLink-Diagnostic-Probe.exe" })
                    File.Delete(Path.Combine(operation, file));
                Directory.Delete(operation);
            }
        }
        catch (Exception error) { trial.Failure = ProxyTunSession.SafeCode(error); }
        var after = await ProxyTunSession.SnapshotAsync(SnapshotScript);
        trial.Samples.Add(Sample("after-stop", baseline, after, index, identity));
        trial.CleanupConfirmed = coreExited && address is not null && OwnFootprintAbsent(after, ownedIndex, address);
        try { trial.ProxyAfter = await ProbeAsync(proxy); }
        catch (Exception error) { trial.Failure ??= ProxyTunSession.SafeCode(error); }
        for (int attempt = 1; trial.CleanupConfirmed && !trial.Samples[^1].DefaultRoute && attempt <= 5; attempt++)
        {
            await Task.Delay(1500);
            var recovery = await ProxyTunSession.SnapshotAsync(SnapshotScript);
            trial.Samples.Add(Sample($"recovery-{attempt}", baseline, recovery, index, identity));
        }
    }

    private static void VerifyNoConflicts(JsonObject baseline, LocalProxyEndpoint proxy, bool isolatedFixture)
    {
        if (!RuntimePreflight.IsAdministrator() || RuntimePreflight.GetConflicts().Count != 0
            || (!isolatedFixture && (int?)baseline["Proxy"]?["Enable"] != 1) || (bool?)baseline["Physical"]?["Hardware"] != true
            || Rows(baseline, "Adapters").Any(row => (string?)row["Name"] is ProxyTunPlan.AdapterName or "xray_tun")
            || Rows(baseline, "Routes").Any(row => (string?)row["DestinationPrefix"] is "0.0.0.0/1" or "128.0.0.0/1" or "::/1" or "8000::/1"))
            throw new IOException("DIAGNOSTIC_PROXY_OR_NETWORK_CONFLICT");
        foreach (var process in Process.GetProcessesByName("sing-box"))
        {
            using (process)
                if (!proxy.Members.Any(member => member.Pid == process.Id && string.Equals(
                    Path.GetFileName(Path.GetDirectoryName(member.Path)), "sing_box", StringComparison.OrdinalIgnoreCase)))
                    throw new IOException("DIAGNOSTIC_OTHER_TRANSPORT_RUNNING");
        }
    }

    private static bool OwnFootprintAbsent(JsonObject after, int? index, string diagnosticPrefix) =>
        !Rows(after, "Adapters").Any(row => (string?)row["Name"] == ProxyTunPlan.AdapterName)
        && (index is null || StateCategories.All(category => !Rows(after, category).Any(row => (int?)row["InterfaceIndex"] == index)))
        && !Rows(after, "Addresses").Any(row => (string?)row["IPAddress"] is { } address
            && SharesDiagnosticSubnet(address, diagnosticPrefix))
        && !Rows(after, "Routes").Any(row => (string?)row["DestinationPrefix"] is { } prefix
            && prefix is not ("0.0.0.0/0" or "::/0") && SharesDiagnosticSubnet(prefix.Split('/')[0], diagnosticPrefix));

    private static bool SharesDiagnosticSubnet(string address, string prefix)
    {
        if (!IPAddress.TryParse(address, out var ip)) return false;
        byte[] reference = IPAddress.Parse(prefix.Split('/')[0]).GetAddressBytes();
        byte[] current = ip.GetAddressBytes();
        // The production planner uses /30 for IPv4.
        return reference.Length == current.Length && reference.AsSpan(0, reference.Length - 1)
            .SequenceEqual(current.AsSpan(0, current.Length - 1)) && (reference[^1] & 0xfc) == (current[^1] & 0xfc);
    }

    private static string CopyProbe(string operation)
    {
        string probe = Path.Combine(operation, "VaKoLink-Diagnostic-Probe.exe");
        File.Copy(Environment.ProcessPath!, probe);
        return probe;
    }

    private static int FreePort()
    {
        using var port = new TcpListener(IPAddress.Loopback, 0);
        port.Start();
        return ((IPEndPoint)port.LocalEndpoint).Port;
    }

    private static JsonObject BuildPlan(LocalProxyEndpoint proxy, string physical, string loopback, string v4,
        int api, string secret, string probe)
    {
        return ProxyTunPlan.Build(proxy, null, physical, loopback, v4, api, secret, selectedApplications: [probe], ipv4Only: true);
    }

    private static IEnumerable<JsonObject> Rows(JsonObject snapshot, string property) =>
        (snapshot[property] as JsonArray ?? []).OfType<JsonObject>();
    private static bool HasDefault(JsonObject snapshot, int index) => Rows(snapshot, "Routes")
        .Any(row => (int?)row["InterfaceIndex"] == index && (string?)row["DestinationPrefix"] == "::/0");
    private static SafeSample Sample(string phase, JsonObject baseline, JsonObject now, int index, string identity)
    {
        var native = Rows(now, "NativeInterfaces").SingleOrDefault(row => (int?)row["InterfaceIndex"] == index);
        int Count(string property) => Rows(now, property).Count(row => (int?)row["InterfaceIndex"] == index && (int?)row["AddressFamily"] == 23);
        JsonArray OtherDefaults(JsonObject snapshot) => new(Rows(snapshot, "Routes").Where(row =>
            (int?)row["InterfaceIndex"] != index && (string?)row["DestinationPrefix"] is "::/0" or "0.0.0.0/0")
            .Select(row => row.DeepClone()).ToArray());
        return new(phase, DateTimeOffset.UtcNow, native is not null && (string?)native["Guid"] == identity,
            (int?)native?["TunnelType"], HasDefault(now, index), Count("Addresses"), Count("Routes"),
            ProxyNetworkIsolation.Equivalent(baseline["Proxy"], now["Proxy"]),
            ProxyNetworkIsolation.EquivalentDnsServers(baseline["DNS"], now["DNS"]),
            ProxyNetworkIsolation.Equivalent(OtherDefaults(baseline), OtherDefaults(now)));
    }

    private static async Task<int> CheckInstalledFilesAsync()
    {
        string result = Path.Combine(AppContext.BaseDirectory, "self-check.txt");
        string config = Path.Combine(AppContext.BaseDirectory, "self-check-config.json");
        try
        {
            using var core = OpenVerifiedCore();
            var proxy = new LocalProxyEndpoint("127.0.0.1", 10808, 0, DateTime.UnixEpoch, 0, []);
            var plan = BuildPlan(proxy, "Ethernet", "Loopback", "172.29.16.1/30", FreePort(),
                Convert.ToHexString(RandomNumberGenerator.GetBytes(32)), Environment.ProcessPath!);
            var tun = plan["inbounds"]![0]!;
            if ((bool?)tun["auto_route"] != true || (string?)tun["dns_mode"] != "disabled"
                || tun["address"] is not JsonArray { Count: 1 } ipv4 || (string?)ipv4[0] != "172.29.16.1/30")
                throw new IOException("DIAGNOSTIC_SELF_CHECK_WRONG_VARIANT");
            await File.WriteAllTextAsync(config, plan.ToJsonString());
            await ProxyTunSession.CheckAsync(config);
            var snapshot = await ProxyTunSession.SnapshotAsync(SnapshotScript);
            var sample = Sample("synthetic-check", snapshot, snapshot, -1, "");
            if (!sample.ProxyUnchanged || !sample.DnsUnchanged || !sample.OtherDefaultsUnchanged)
                throw new IOException("DIAGNOSTIC_SELF_CHECK_PROJECTION_FAILED");
            if (!SharesDiagnosticSubnet("172.29.16.3", "172.29.16.1/30")
                || SharesDiagnosticSubnet("172.29.16.4", "172.29.16.1/30"))
                throw new IOException("DIAGNOSTIC_SELF_CHECK_CLEANUP_FAILED");
            string work = Path.Combine(Path.GetDirectoryName(result)!, "self-check-probe-" + Guid.NewGuid().ToString("N"));
            TunPrivateStore.EnsurePrivate(work);
            string probe = CopyProbe(work);
            try
            {
                if (await RoutedDiagnosticProbe.TestLocalFilterAsync(probe, runWithoutFilter: true) != 0)
                    throw new IOException("DIAGNOSTIC_SELF_CHECK_LOOPBACK_PRECHECK_FAILED");
                using (new ApplicationIpv6Guard([probe]))
                {
                    if (await RoutedDiagnosticProbe.TestLocalFilterAsync(probe) != 3)
                        throw new IOException("DIAGNOSTIC_SELF_CHECK_FILTER_FAILED");
                    if (await RoutedDiagnosticProbe.TestLocalFilterAsync(Environment.ProcessPath!, runWithoutFilter: true) != 0)
                        throw new IOException("DIAGNOSTIC_SELF_CHECK_FILTER_SCOPE_FAILED");
                }
                if (await RoutedDiagnosticProbe.TestLocalFilterAsync(probe, runWithoutFilter: true) != 0)
                    throw new IOException("DIAGNOSTIC_SELF_CHECK_FILTER_CLEANUP_FAILED");
            }
            finally { File.Delete(probe); Directory.Delete(work); }
            RotationFixture.Check();
            await File.WriteAllTextAsync(result, "PASS: production Teredo rotation and strict negative cases, release core, routed IPv4 configuration, Windows snapshot, production WFP TCP and UDP process scope and filter removal.");
            return 0;
        }
        catch (Exception error)
        {
            await File.WriteAllTextAsync(result, "FAIL: " + ProxyTunSession.SafeCode(error));
            return 1;
        }
        finally { File.Delete(config); }
    }

    private static async Task<int> CheckLocalRouteAsync()
    {
        string report = Path.Combine(AppContext.BaseDirectory, "local-route.json");
        string config = Path.Combine(AppContext.BaseDirectory, "local-socks-fixture.json");
        Process? socks = null;
        var trial = new Trial();
        try
        {
            using var core = OpenVerifiedCore();
            var before = await StableSnapshotAsync();
            int port = FreePort();
            var xray = Path.Combine(AppContext.BaseDirectory, "fixture-xray", "xray.exe");
            await File.WriteAllTextAsync(config, $$$"""
                {"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":{{{port}}},"protocol":"socks","settings":{"auth":"noauth","udp":true}}],
                "outbounds":[{"protocol":"freedom"}]}
                """);
            var start = new ProcessStartInfo(xray) { UseShellExecute = false, CreateNoWindow = true };
            start.ArgumentList.Add("run");
            start.ArgumentList.Add("-c");
            start.ArgumentList.Add(config);
            socks = Process.Start(start) ?? throw new IOException("FIXTURE_SOCKS_START_FAILED");
            await Task.Delay(500);
            var birth = socks.StartTime.ToUniversalTime();
            var proxy = new LocalProxyEndpoint("127.0.0.1", port, socks.Id, birth, 0, [new(socks.Id, xray, birth)]);
            await RunTrialAsync(trial, proxy, before, -1, "", isolatedFixture: true);
        }
        catch (Exception error) { trial.Failure = ProxyTunSession.SafeCode(error); }
        finally
        {
            if (socks is { HasExited: false }) { socks.Kill(); await socks.WaitForExitAsync(); }
            socks?.Dispose();
            File.Delete(config);
        }
        await File.WriteAllTextAsync(report, JsonSerializer.Serialize(trial, ReportOptions));
        return trial.HttpsPassed && trial.CleanupConfirmed && trial.Ipv6GuardRemoved ? 0 : 1;
    }

    private sealed class DiagnosticReport
    {
        public string DiagnosticVersion => "1.30-teredo-routed";
        public DateTimeOffset StartedUtc { get; init; }
        public DateTimeOffset CompletedUtc { get; set; }
        public SafeProbe? ProxyBefore { get; set; }
        public string? Blocker { get; set; }
        public Trial? Trial { get; set; }
    }

    private sealed class Trial
    {
        public bool AutoRoute => true;
        public bool Ipv6AddressConfigured => false;
        public bool AdapterObserved { get; set; }
        public bool Ipv6GuardActive { get; set; }
        public bool Ipv6TcpBlocked { get; set; }
        public bool Ipv6UdpBlocked { get; set; }
        public bool Ipv6GuardRemoved { get; set; }
        public bool SocksChainObserved { get; set; }
        public bool HttpsPassed { get; set; }
        public int? ProbeExitCode { get; set; }
        public List<int> OwnIpv6AddressRows { get; } = [];
        public DateTimeOffset? CoreStartUtc { get; set; }
        public DateTimeOffset? CoreStopUtc { get; set; }
        public string? Failure { get; set; }
        public bool CleanupConfirmed { get; set; }
        public SafeProbe? ProxyAfter { get; set; }
        public List<SafeSample> Samples { get; } = [];
        public List<SafeAudit> Audit { get; } = [];
    }

    private sealed record SafeProbe(bool Ready, bool Socks5, bool Tcp, bool Udp, long Milliseconds);
    private sealed record SafeSample(string Phase, DateTimeOffset Utc, bool SameIdentity, int? TunnelType, bool DefaultRoute,
        int AddressRows, int RouteRows, bool ProxyUnchanged, bool DnsUnchanged, bool OtherDefaultsUnchanged);
    private sealed record SafeAudit(int Snapshot, bool Passed, string? Failure, IReadOnlyList<NetworkInterfaceReport> Interfaces);
}
