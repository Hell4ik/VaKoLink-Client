using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace VakoLink.AntiDpi.Windows;

// Actual datagrams through an authenticated loopback inbound, the same SOCKS outbound as Discord,
// the live V2rayN UDP relay, and an external DNS responder. Never a TCP-only readiness substitute.
public static class DiscordUdpProbe
{
    public static async Task<JsonObject> RunAsync(int port, string secret, Func<Task>? observe = null, int samples = 2, int intervalMs = 300)
    {
        if (samples is < 2 or > 6 || intervalMs is < 0 or > 15000) throw new ArgumentOutOfRangeException(nameof(samples));
        var started = DateTimeOffset.UtcNow; var watch = Stopwatch.StartNew();
        using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(12000 + (samples - 1) * intervalMs)); var token = timeout.Token;
        using var control = new TcpClient(); await control.ConnectAsync(IPAddress.Loopback, port, token); var s = control.GetStream();
        await s.WriteAsync(new byte[] { 5, 1, 2 }, token); var two = new byte[2]; await s.ReadExactlyAsync(two, token);
        if (two[0] != 5 || two[1] != 2) throw new IOException("DISCORD_UDP_PROBE_AUTH_METHOD");
        byte[] user = Encoding.ASCII.GetBytes("probe"), pass = Encoding.ASCII.GetBytes(secret);
        await s.WriteAsync(new byte[] { 1, (byte)user.Length }.Concat(user).Append((byte)pass.Length).Concat(pass).ToArray(), token);
        await s.ReadExactlyAsync(two, token); if (two[0] != 1 || two[1] != 0) throw new IOException("DISCORD_UDP_PROBE_AUTH_FAILED");
        await s.WriteAsync(new byte[] { 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 }, token);
        var head = new byte[4]; await s.ReadExactlyAsync(head, token);
        if (head[0] != 5 || head[1] != 0 || head[2] != 0 || head[3] is not (1 or 4)) throw new IOException("DISCORD_UDP_ASSOCIATE_REJECTED");
        int n = head[3] == 1 ? 4 : 16; var bound = new byte[n + 2]; await s.ReadExactlyAsync(bound, token);
        var relay = new IPAddress(bound.AsSpan(0, n)); if (relay.Equals(IPAddress.Any) || relay.Equals(IPAddress.IPv6Any)) relay = relay.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Loopback : IPAddress.IPv6Loopback;
        if (!IPAddress.IsLoopback(relay)) throw new IOException("DISCORD_UDP_RELAY_NOT_LOCAL");
        using var udp = new UdpClient(relay.AddressFamily); udp.Connect(relay, bound[n] * 256 + bound[n + 1]);
        var rtts = new List<double>();
        for (int i = 0; i < samples; i++)
        {
            byte[] dns = Convert.FromHexString("000001000001000000000000076578616D706C6503636F6D0000010001");
            RandomNumberGenerator.Fill(dns.AsSpan(0, 2));
            byte[] request = new byte[] { 0, 0, 0, 1, 1, 1, 1, 1, 0, 53 }.Concat(dns).ToArray();
            var rtt = Stopwatch.StartNew(); await udp.SendAsync(request, token); var response = await udp.ReceiveAsync(token);
            if (!ValidReply(response.Buffer, request)) throw new IOException("DISCORD_UDP_RESPONSE_INVALID");
            rtts.Add(rtt.Elapsed.TotalMilliseconds);
            if (observe is not null) await observe();
            if (i + 1 < samples) await Task.Delay(intervalMs, token);
        }
        return new JsonObject { ["Passed"] = true, ["Utc"] = started, ["DurationMs"] = watch.ElapsedMilliseconds,
            ["DatagramsSent"] = samples, ["ValidatedReplies"] = samples, ["SameAssociation"] = true, ["IntervalMs"] = intervalMs, ["RoundTripMs"] = new JsonArray(rtts.Select(x => (JsonNode?)JsonValue.Create(Math.Round(x, 1))).ToArray()),
            ["Path"] = "authenticated loopback SOCKS → discord-media → V2rayN SOCKS5 UDP → external DNS response",
            ["VoiceOrVideoVerified"] = false, ["Limits"] = "Small DNS datagrams, not Discord destination/MTU/media quality; node country and its remote transport unknown" };
    }
    public static bool ValidReply(byte[] data, byte[] request) => data.Length >= 22 && request.Length >= 22
        && data.AsSpan(0, 10).SequenceEqual(request.AsSpan(0, 10)) && data[10] == request[10] && data[11] == request[11]
        && (data[12] & 128) != 0 && (data[13] & 15) == 0;
}
