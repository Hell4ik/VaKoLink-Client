using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace VakoLink.AntiDpi.Windows;

public static class ProxyHealthCheck
{
    public const int DefaultProtocolTimeoutMilliseconds = 14000, MaximumAttemptsPerProtocol = 2;
    // Only fixed public control targets through the discovered proxy, never a LAN scan or a direct fallback.
    private static readonly string[] TcpTargets = ["example.com", "example.org"];
    private static readonly byte[][] UdpTargets = [[1, 1, 1, 1], [8, 8, 8, 8]];

    public static async Task<ProxyProbe> RunAsync(LocalProxyEndpoint endpoint, int protocolTimeoutMilliseconds = DefaultProtocolTimeoutMilliseconds)
    {
        if (protocolTimeoutMilliseconds is < 100 or > DefaultProtocolTimeoutMilliseconds) throw new ArgumentOutOfRangeException(nameof(protocolTimeoutMilliseconds));
        var watch = Stopwatch.StartNew();
        // Independent deadlines: a slow HTTP control must never consume UDP's test budget or prevent its execution.
        var tcpTask = ProtocolAsync(endpoint, false, protocolTimeoutMilliseconds);
        var udpTask = ProtocolAsync(endpoint, true, protocolTimeoutMilliseconds);
        await Task.WhenAll(tcpTask, udpTask);
        var tcp = await tcpTask; var udp = await udpTask;
        bool t = tcp.Any(a => a.Passed), u = udp.Any(a => a.Passed);
        var attempts = tcp.Concat(udp).ToArray();
        string? fatal = attempts.FirstOrDefault(a => a.Failure is "PROXY_AUTH_REQUIRED" or "PROXY_NOT_SOCKS5" or "PROXY_UDP_RELAY_NOT_LOCAL")?.Failure;
        string? failure = fatal ?? (!t ? tcp.Last().Failure : !u ? udp.Last().Failure : null);
        return new(attempts.Any(a => a.Socks5), t, u, failure, DateTimeOffset.UtcNow, attempts, watch.ElapsedMilliseconds);
    }

    private static async Task<IReadOnlyList<ProxyProbeAttempt>> ProtocolAsync(LocalProxyEndpoint endpoint, bool udp, int timeoutMs)
    {
        using var deadline = new CancellationTokenSource(timeoutMs);
        try
        {
            var primary = AttemptAsync(endpoint, udp, 0, deadline.Token);
            // At half the existing protocol budget, hedge an unresponsive target without cancelling it.
            // A primary response at 9 seconds is still valid; a 7-second per-target cutoff would regress the user's observed 9-second success.
            await Task.WhenAny(primary, Task.Delay(timeoutMs / 2, deadline.Token));
            if (primary.IsCompleted)
            {
                var first = await primary;
                if (first.Passed || !Retryable(first) || deadline.IsCancellationRequested) return [first];
            }
            var alternative = AttemptAsync(endpoint, udp, 1, deadline.Token);
            var completed = await Task.WhenAny(primary, alternative); var result = await completed;
            var other = completed == primary ? alternative : primary;
            if (result.Passed)
            {
                bool wasPending = !other.IsCompleted; deadline.Cancel(); var retired = await other;
                if (wasPending && retired.Failure is "PROXY_TCP_RESPONSE_TIMEOUT" or "PROXY_UDP_RESPONSE_TIMEOUT")
                    retired = retired with { Failure = "PROBE_SUPERSEDED_AFTER_SUCCESS" };
                return completed == primary ? [result, retired] : [retired, result];
            }
            var remaining = await other;
            return completed == primary ? [result, remaining] : [remaining, result];
        }
        finally { deadline.Cancel(); }
    }
    private static bool Retryable(ProxyProbeAttempt attempt) => attempt.Stage is "TcpConnectReply" or "TcpResponse" or "UdpResponse"
        && attempt.Failure is not ("PROXY_AUTH_REQUIRED" or "PROXY_NOT_SOCKS5" or "PROXY_UDP_RELAY_NOT_LOCAL");

    private static async Task<ProxyProbeAttempt> AttemptAsync(LocalProxyEndpoint endpoint, bool udp, int i, CancellationToken token)
    {
        var watch = Stopwatch.StartNew(); string stage = "LocalSocketConnect"; bool socks = false;
        string target = udp ? "udp-dns-" + (i == 0 ? "cloudflare" : "google") : "tcp-http-" + TcpTargets[i];
        void Progress(string s) { stage = s; if (s == "Socks5Negotiated") socks = true; }
        try
        {
            if (!udp)
            {
                using var c = await LocalProxy.ConnectAsync(endpoint, 1, TcpTargets[i], 80, token, Progress);
                stage = "TcpResponse";
                await c.GetStream().WriteAsync(Encoding.ASCII.GetBytes($"HEAD / HTTP/1.1\r\nHost: {TcpTargets[i]}\r\nConnection: close\r\n\r\n"), token);
                var b = new byte[12]; await c.GetStream().ReadExactlyAsync(b, token);
                if (!Encoding.ASCII.GetString(b).StartsWith("HTTP/1.", StringComparison.Ordinal)) throw new IOException("PROXY_TCP_RESPONSE_INVALID");
            }
            else
            {
                // RFC1928: retain the TCP control for the entire UDP association, including receipt/validation.
                using var control = await LocalProxy.ConnectAsync(endpoint, 3, "0.0.0.0", 0, token, Progress);
                stage = "UdpResponse"; var relay = LocalProxy.Relay(control);
                using var socket = new UdpClient(relay.AddressFamily); socket.Connect(relay);
                var query = Convert.FromHexString("000001000001000000000000076578616D706C6503636F6D0000010001");
                RandomNumberGenerator.Fill(query.AsSpan(0, 2));
                var packet = new byte[] { 0, 0, 0, 1 }.Concat(UdpTargets[i]).Concat(new byte[] { 0, 53 }).Concat(query).ToArray();
                await socket.SendAsync(packet, token); var response = await socket.ReceiveAsync(token);
                if (!DiscordUdpProbe.ValidReply(response.Buffer, packet)) throw new IOException("PROXY_UDP_RESPONSE_INVALID");
            }
            return new(udp ? "udp" : "tcp", target, stage, socks, true, null, watch.ElapsedMilliseconds);
        }
        catch (Exception ex)
        {
            string error = ex is OperationCanceledException ? "PROXY_" + (udp ? "UDP" : "TCP") + "_RESPONSE_TIMEOUT"
                : ex is SocketException && stage == "LocalSocketConnect" ? "PROXY_LOCAL_SOCKET_UNAVAILABLE" : ProxyTunSession.SafeCode(ex);
            return new(udp ? "udp" : "tcp", target, stage, socks, false, error, watch.ElapsedMilliseconds);
        }
    }
}
