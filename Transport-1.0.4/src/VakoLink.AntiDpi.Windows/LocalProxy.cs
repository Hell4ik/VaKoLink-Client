using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;

namespace VakoLink.AntiDpi.Windows;

public sealed record LocalProxyMember(int Pid, string Path, DateTime BirthUtc);
public sealed record LocalProxyConfiguration(string Path, string Hash);
public sealed record LocalProxyEndpoint(string Host, int Port, int OwnerPid, DateTime OwnerBirthUtc, int GuiPid, IReadOnlyList<LocalProxyMember> Members, IReadOnlyList<LocalProxyConfiguration>? Configurations = null)
{
    public override string ToString() => $"Локальный вход · {Host}:{Port} · V2rayN {GuiPid}";
    public void VerifyAlive()
    {
        try
        {
            foreach (var m in Members)
            {
                using var p = Process.GetProcessById(m.Pid);
                if (p.HasExited || p.StartTime.ToUniversalTime() != m.BirthUtc.ToUniversalTime() ||
                    !string.Equals(p.MainModule?.FileName, m.Path, StringComparison.OrdinalIgnoreCase)) throw new IOException("PROXY_OWNER_CHANGED");
            }
            foreach (var c in Configurations ?? [])
            {
                TunPrivateStore.VerifyImagePath(c.Path);
                if (!File.Exists(c.Path) || AionTunPlan.FileHash(c.Path) != c.Hash) throw new IOException("PROXY_CONFIGURATION_CHANGED");
            }
        }
        catch (ArgumentException) { throw new IOException("V2RAY_EXITED"); }
    }
}
public sealed record ProxyProbeAttempt(string Protocol, string Target, string Stage, bool Socks5, bool Passed,
    string? Failure, long DurationMs);
public sealed record ProxyProbe(bool Socks5, bool TcpResponse, bool UdpResponse, string? Failure, DateTimeOffset Utc,
    IReadOnlyList<ProxyProbeAttempt>? Attempts = null, long DurationMs = 0)
{
    public bool Ready => Socks5 && TcpResponse && UdpResponse && Failure is null;
}
public static class LocalProxy
{
    public static async Task<IReadOnlyList<LocalProxyEndpoint>> DiscoverAsync(string script)
    {
        var psi = new ProcessStartInfo("powershell.exe") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        psi.Environment["PSModulePath"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\WindowsPowerShell\v1.0\Modules");
        foreach (var a in new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script }) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!; var output = p.StandardOutput.ReadToEndAsync(); var err = p.StandardError.ReadToEndAsync();
        try { await p.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15)); } catch { p.Kill(); throw new IOException("PROXY_DISCOVERY_TIMEOUT"); }
        await err; var json = await output;
        if (p.ExitCode != 0 || json.Length > 128000) throw new IOException("PROXY_DISCOVERY_FAILED");
        return ParseDiscovery(JsonNode.Parse(json)!.AsArray());
    }
    public static IReadOnlyList<LocalProxyEndpoint> ParseDiscovery(JsonArray roots)
    {
        var result = new List<LocalProxyEndpoint>();
        foreach (var root in roots.Take(8))
        {
            if ((bool?)root?["TunEnabled"] == true) continue;
            var members = root!["Members"]!.AsArray().Select(n => new LocalProxyMember((int)n!["Pid"]!, (string?)n["Path"] ?? "", DateTime.Parse((string)n["BirthUtc"]!, null, System.Globalization.DateTimeStyles.RoundtripKind))).ToArray();
            // Without paths we cannot establish loop exclusions; elevated discovery must precede activation.
            if (members.Length == 0 || members.Any(m => !Path.IsPathFullyQualified(m.Path))) continue;
            foreach (var n in root["Listeners"]!.AsArray().Take(32))
            {
                int pid = (int)n!["Pid"]!, port = (int)n["Port"]!; string host = (string)n["Host"]!;
                var owner = members.SingleOrDefault(m => m.Pid == pid);
                if (owner is null || port is < 1 or > 65535 || !IPAddress.TryParse(host, out var ip) || !IPAddress.IsLoopback(ip)) continue;
                var configurations = (root["Configurations"] as JsonArray)?.Select(c => new LocalProxyConfiguration((string)c!["Path"]!, (string)c["Hash"]!)).ToArray() ?? [];
                result.Add(new(host, port, pid, owner.BirthUtc, (int)root["GuiPid"]!, members, configurations));
            }
        }
        return result.DistinctBy(x => (x.Host, x.Port, x.OwnerPid)).ToArray();
    }
    public static async Task<TcpClient> ConnectAsync(LocalProxyEndpoint endpoint, byte command, string host, int port, CancellationToken token,
        Action<string>? progress = null)
    {
        var client = new TcpClient(IPAddress.Parse(endpoint.Host).AddressFamily);
        try
        {
            progress?.Invoke("LocalSocketConnect");
            await client.ConnectAsync(endpoint.Host, endpoint.Port, token); var s = client.GetStream();
            progress?.Invoke("SocksGreeting");
            await s.WriteAsync(new byte[] { 5, 1, 0 }, token); var b = new byte[2]; await s.ReadExactlyAsync(b, token);
            if (b[0] != 5 || b[1] != 0) throw new IOException(b[0] == 5 && b[1] == 2 ? "PROXY_AUTH_REQUIRED" : "PROXY_NOT_SOCKS5");
            progress?.Invoke("Socks5Negotiated");
            byte[] address = IPAddress.TryParse(host, out var ip) ? new byte[] { ip.AddressFamily == AddressFamily.InterNetwork ? (byte)1 : (byte)4 }.Concat(ip.GetAddressBytes()).ToArray()
                : new byte[] { 3, checked((byte)Encoding.ASCII.GetByteCount(host)) }.Concat(Encoding.ASCII.GetBytes(host)).ToArray();
            await s.WriteAsync(new byte[] { 5, command, 0 }.Concat(address).Concat(new byte[] { (byte)(port >> 8), (byte)port }).ToArray(), token);
            progress?.Invoke(command == 3 ? "UdpAssociateReply" : "TcpConnectReply");
            var head = new byte[4]; await s.ReadExactlyAsync(head, token);
            if (head[0] != 5 || head[2] != 0 || head[1] != 0) throw new IOException(command == 3 ? "PROXY_UDP_ASSOCIATE_REJECTED" : "PROXY_CONNECT_REJECTED");
            int len = head[3] == 1 ? 4 : head[3] == 4 ? 16 : head[3] == 3 ? await ReadByteAsync(s, token) : throw new IOException("PROXY_REPLY_INVALID");
            var bound = new byte[len + 2]; await s.ReadExactlyAsync(bound, token);
            if (command == 3)
            {
                if (head[3] == 3) throw new IOException("PROXY_UDP_RELAY_NOT_LOCAL");
                var relay = new IPAddress(bound.AsSpan(0, len)); if (relay.Equals(IPAddress.Any) || relay.Equals(IPAddress.IPv6Any)) relay = IPAddress.Parse(endpoint.Host);
                // Never follow an arbitrary UDP relay address returned by a local untrusted socket.
                if (!IPAddress.IsLoopback(relay)) throw new IOException("PROXY_UDP_RELAY_NOT_LOCAL");
                client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                Relays.Add(client, new IPEndPoint(relay, bound[^2] * 256 + bound[^1]));
            }
            return client;
        }
        catch { client.Dispose(); throw; }
    }
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<TcpClient, IPEndPoint> Relays = new();
    private static async Task<int> ReadByteAsync(NetworkStream s, CancellationToken t) { var b = new byte[1]; await s.ReadExactlyAsync(b, t); return b[0]; }
    internal static IPEndPoint Relay(TcpClient client) => Relays.GetValue(client, _ => throw new IOException("PROXY_RELAY_MISSING"));
    public static Task<ProxyProbe> ProbeAsync(LocalProxyEndpoint endpoint) => ProxyHealthCheck.RunAsync(endpoint);
}
