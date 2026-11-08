using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;

namespace VakoLink.AntiDpi.Windows;

public sealed record ConnectivityStage(string Stage, DateTimeOffset StartedUtc, DateTimeOffset FinishedUtc, string Result, string? ErrorType,
    string? FailureReason = null, IReadOnlyList<ConnectivityError>? Errors = null,
    bool TrialStopRequested = false, bool ProbeDeadlineExpired = false);
public sealed record ConnectivityError(string Type, int HResult, string? SocketCode);
public sealed record DiscordConnectivityEvidence(IReadOnlyList<ConnectivityStage> Stages, int DnsIpv4, int DnsIpv6,
    string? TcpAddressFamily, string? TlsProtocol, int? HttpStatus, bool GatewayHello,
    string Scope = "Unauthenticated synthetic probe from recorder process, NOT selected Discord process; not proof of client loading or voice. No Identify, tokens, payload logging or media.");

public static class DiscordConnectivityProbe
{
    internal static IReadOnlyList<ConnectivityError> SafeErrors(Exception error)
    {
        var result = new List<ConnectivityError>();
        for (var next = error; next is not null && result.Count < 4; next = next.InnerException!)
            result.Add(new(next.GetType().Name, next.HResult, next is SocketException socket ? socket.SocketErrorCode.ToString() : null));
        return result.ToArray(); // Never messages, hosts, endpoints, credentials or stack traces.
    }
    public static async Task<DiscordConnectivityEvidence> RunAsync(CancellationToken token = default)
    {
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(token);
        bounded.CancelAfter(TimeSpan.FromSeconds(20)); var ct = bounded.Token;
        var stages = new List<ConnectivityStage>();
        int ipv4 = 0, ipv6 = 0; string? family = null, tlsProtocol = null; int? status = null; bool hello = false;
        async Task<bool> Stage(string name, Func<Task> work)
        {
            var started = DateTimeOffset.UtcNow;
            try { await work(); stages.Add(new(name, started, DateTimeOffset.UtcNow, "Passed", null)); return true; }
            catch (Exception ex) when (ex is SocketException or IOException or System.Security.Authentication.AuthenticationException
                or WebSocketException or OperationCanceledException or JsonException or InvalidOperationException)
            {
                var errors = SafeErrors(ex);
                var cancelled = errors.Any(error => error.Type is "OperationCanceledException" or "TaskCanceledException");
                var reason = cancelled ? token.IsCancellationRequested ? "CancelledByTrialStop" : ct.IsCancellationRequested ? "BoundedProbeDeadline" : "UnexpectedCancellation"
                    : ex is SocketException ? "SocketError" : ex is IOException or System.Security.Authentication.AuthenticationException ? "TlsOrIoError" : "ProtocolError";
                stages.Add(new(name, started, DateTimeOffset.UtcNow, "Failed", ex.GetType().Name, reason, errors,
                    token.IsCancellationRequested, ct.IsCancellationRequested && !token.IsCancellationRequested)); return false;
            }
        }
        IPAddress[] addresses = [];
        if (!await Stage("DNS_DISCORD", async () =>
        {
            addresses = await Dns.GetHostAddressesAsync("discord.com", ct);
            ipv4 = addresses.Count(a => a.AddressFamily == AddressFamily.InterNetwork);
            ipv6 = addresses.Count(a => a.AddressFamily == AddressFamily.InterNetworkV6);
        })) return Result();
        using var tcp = new TcpClient();
        if (!await Stage("TCP_DISCORD_443", async () =>
        {
            // Explicit IPv4 control probe; IPv6 necessity comes from the actual selected TCP table/copies.
            var address = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                ?? throw new InvalidOperationException("DNS_IPV4_ABSENT");
            await tcp.ConnectAsync(address, 443, ct); family = "IPv4";
        })) return Result();
        using var tls = new SslStream(tcp.GetStream(), false); // Standard certificate validation; no MITM.
        if (!await Stage("TLS_DISCORD", async () =>
        { await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "discord.com" }, ct); tlsProtocol = tls.SslProtocol.ToString(); })) return Result();
        if (!await Stage("HTTPS_DISCORD_GATEWAY_ENDPOINT", async () =>
        {
            var request = Encoding.ASCII.GetBytes("GET /api/v10/gateway HTTP/1.1\r\nHost: discord.com\r\nConnection: close\r\n\r\n");
            await tls.WriteAsync(request, ct);
            var header = new byte[8192]; int used = 0;
            while (used < header.Length)
            {
                var size = await tls.ReadAsync(header.AsMemory(used, 1), ct); if (size == 0) throw new IOException(); used += size;
                if (used >= 4 && header.AsSpan(used - 4, 4).SequenceEqual("\r\n\r\n"u8)) break;
            }
            var first = Encoding.ASCII.GetString(header.AsSpan(0, used)).Split('\r')[0].Split(' ');
            if (first.Length < 2 || !int.TryParse(first[1], out var parsed) || parsed is < 100 or > 599) throw new IOException();
            status = parsed; // A response, not inferred logged-in UI success.
        })) return Result();
        using var websocket = new ClientWebSocket();
        if (!await Stage("GATEWAY_WSS_HTTP_UPGRADE", async () =>
            await websocket.ConnectAsync(new Uri("wss://gateway.discord.gg/?v=10&encoding=json"), ct))) return Result();
        await Stage("GATEWAY_PUBLIC_HELLO", async () =>
        {
            var buffer = new byte[16384]; int used = 0; WebSocketReceiveResult part;
            do
            {
                if (used == buffer.Length) throw new IOException();
                part = await websocket.ReceiveAsync(new ArraySegment<byte>(buffer, used, buffer.Length - used), ct); used += part.Count;
                if (part.MessageType != WebSocketMessageType.Text) throw new IOException();
            } while (!part.EndOfMessage);
            using var json = JsonDocument.Parse(buffer.AsMemory(0, used));
            hello = json.RootElement.TryGetProperty("op", out var op) && op.TryGetInt32(out var opcode) && opcode == 10;
            if (!hello) throw new IOException();
        });
        websocket.Abort(); // Never Identify, authenticate, read guilds or transmit voice.
        return Result();
        DiscordConnectivityEvidence Result() => new(stages.ToArray(), ipv4, ipv6, family, tlsProtocol, status, hello);
    }
}
