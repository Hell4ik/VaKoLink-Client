using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using VakoLink.AntiDpi.Windows;

internal static class RoutedDiagnosticProbe
{
    internal const string Destination = "1.1.1.1";
    private const string HttpsName = "one.one.one.one";
    private const int IpUnicastInterface = 31;

    internal static async Task<int> TestIpv6LoopbackAsync(int tcpPort, int udpPort)
    {
        using var timer = new CancellationTokenSource(TimeSpan.FromSeconds(4));
        int result = 0;
        using var tcp = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
        try { await tcp.ConnectAsync(IPAddress.IPv6Loopback, tcpPort, timer.Token); }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.AccessDenied) { result |= 1; }
        catch { return 4; }
        using var udp = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            await udp.ConnectAsync(IPAddress.IPv6Loopback, udpPort, timer.Token);
            await udp.SendAsync(new byte[] { 1 }, SocketFlags.None, timer.Token);
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.AccessDenied) { result |= 2; }
        catch { return 4; }
        return result;
    }

    internal static async Task<int> RequestAsync(string localAddress, int interfaceIndex, string directory)
    {
        using var timer = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.SetSocketOption(SocketOptionLevel.IP, (SocketOptionName)IpUnicastInterface, IPAddress.HostToNetworkOrder(interfaceIndex));
            socket.Bind(new IPEndPoint(IPAddress.Parse(localAddress), 0));
            // Give the parent a real connection to inspect while withholding the HTTPS request.
            await socket.ConnectAsync(IPAddress.Parse(Destination), 443, timer.Token);
            File.WriteAllText(Path.Combine(directory, "ready"), ((IPEndPoint)socket.LocalEndPoint!).Port.ToString());
            while (!File.Exists(Path.Combine(directory, "confirmed"))) await Task.Delay(100, timer.Token);
            using var tls = new SslStream(new NetworkStream(socket));
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = HttpsName }, timer.Token);
            await tls.WriteAsync(Encoding.ASCII.GetBytes($"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {HttpsName}\r\nConnection: close\r\n\r\n"), timer.Token);
            using var reader = new StreamReader(tls, Encoding.ASCII);
            string? status = await reader.ReadLineAsync(timer.Token);
            return status?.StartsWith("HTTP/1.1 200 ", StringComparison.Ordinal) == true ? 0 : 12;
        }
        catch (SocketException error) { return 100000 + (int)error.SocketErrorCode; }
        catch (OperationCanceledException) { return 13; }
        catch { return 14; }
    }

    internal static async Task<int> TestLocalFilterAsync(string probe, bool runWithoutFilter = false)
    {
        using var tcp = new TcpListener(IPAddress.IPv6Loopback, 0);
        using var udp = new UdpClient(new IPEndPoint(IPAddress.IPv6Loopback, 0));
        tcp.Start();
        using var process = Start(probe, "--probe-local-v6", ((IPEndPoint)tcp.LocalEndpoint).Port.ToString(),
            ((IPEndPoint)udp.Client.LocalEndPoint!).Port.ToString());
        await WaitAsync(process, TimeSpan.FromSeconds(9));
        await Task.Delay(250);
        int result = process.ExitCode;
        bool tcpReceived = tcp.Pending();
        bool udpReceived = udp.Available != 0;
        if (runWithoutFilter && result == 0 && tcpReceived && udpReceived) return 0;
        if (!runWithoutFilter && result is 1 or 3 && !tcpReceived && !udpReceived) return 3;
        throw new IOException($"DIAGNOSTIC_IPV6_LOOPBACK_RESULT_{result}_TCP_{Convert.ToInt32(tcpReceived)}_UDP_{Convert.ToInt32(udpReceived)}");
    }

    internal static async Task<(bool ChainSeen, int? ExitCode)> RunAsync(string probe, string directory,
        int index, string address, int apiPort, string apiSecret)
    {
        using var api = new HttpClient(new HttpClientHandler { UseProxy = false })
        {
            BaseAddress = new Uri($"http://127.0.0.1:{apiPort}"),
            Timeout = TimeSpan.FromSeconds(1)
        };
        api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiSecret);
        using var process = Start(probe, "--probe-routed-v4", address, index.ToString(), directory);
        bool confirmed = false;
        try
        {
            string ready = Path.Combine(directory, "ready");
            var clock = Stopwatch.StartNew();
            while (!process.HasExited && clock.Elapsed < TimeSpan.FromSeconds(10))
            {
                if (File.Exists(ready) && int.TryParse(await File.ReadAllTextAsync(ready), out int sourcePort)
                    && await WasRoutedAsync(api, probe, sourcePort))
                {
                    confirmed = true;
                    await File.WriteAllTextAsync(Path.Combine(directory, "confirmed"), "");
                    await WaitAsync(process, TimeSpan.FromSeconds(12));
                    return (true, process.ExitCode);
                }
                await Task.Delay(150);
            }
            return (false, process.HasExited ? process.ExitCode : null);
        }
        finally
        {
            if (!process.HasExited) { process.Kill(); await process.WaitForExitAsync(); }
            if (!confirmed && File.Exists(Path.Combine(directory, "confirmed")))
                throw new IOException("DIAGNOSTIC_UNEXPECTED_PROBE_CONFIRMATION");
        }
    }

    private static async Task<bool> WasRoutedAsync(HttpClient api, string probe, int sourcePort)
    {
        try
        {
            var data = JsonNode.Parse(await api.GetStringAsync("/connections"));
            return (data?["connections"] as JsonArray ?? []).Any(flow =>
            {
                var metadata = flow?["metadata"];
                return string.Equals(AionTunPlan.CanonicalProcess((string?)metadata?["processPath"] ?? ""), probe,
                        StringComparison.OrdinalIgnoreCase)
                    && metadata?["sourcePort"]?.ToString() == sourcePort.ToString()
                    && (string?)metadata?["destinationIP"] == Destination
                    && (flow?["chains"] as JsonArray ?? []).Any(tag => (string?)tag == "v2ray-local");
            });
        }
        catch (HttpRequestException) { return false; }
        catch (TaskCanceledException) { return false; }
    }

    private static Process Start(string path, params string[] arguments)
    {
        var info = new ProcessStartInfo { FileName = path, UseShellExecute = false, CreateNoWindow = true };
        foreach (var argument in arguments) info.ArgumentList.Add(argument);
        return Process.Start(info) ?? throw new IOException("DIAGNOSTIC_PROBE_START_FAILED");
    }

    private static async Task WaitAsync(Process process, TimeSpan timeout)
    {
        try { await process.WaitForExitAsync().WaitAsync(timeout); }
        catch (TimeoutException)
        {
            process.Kill();
            await process.WaitForExitAsync();
            throw;
        }
    }
}
