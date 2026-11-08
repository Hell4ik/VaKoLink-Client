using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Net;
using System.Buffers.Binary;
using System.Text.RegularExpressions;
using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public sealed record DiscordComponentPin(string Path, string Sha256);
public static class DiscordMediaProfile
{
    public const string Id = "discord-udp-socks-v1";
    public static IReadOnlyList<DiscordComponentPin> Discover()
    {
        string root = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Discord");
        if (!Directory.Exists(root)) return [];
        var result = new List<DiscordComponentPin>();
        foreach (string dir in Directory.GetDirectories(root, "app-*").OrderDescending().Take(8))
        {
            string image = System.IO.Path.Combine(dir, "Discord.exe");
            if (!File.Exists(image)) continue;
            TunPrivateStore.VerifyImagePath(image);
            if (!AuthenticodeVerifier.IsTrusted(image)) continue;
            using var signed = X509Certificate.CreateFromSignedFile(image); using var cert = new X509Certificate2(signed);
            if (cert.GetNameInfo(X509NameType.SimpleName, false) != "Discord Inc.") continue;
            result.Add(new(image, AionTunPlan.FileHash(image)));
        }
        return result;
    }
    public static object ProcessEvidence(IReadOnlyList<DiscordComponentPin> pins, LocalProxyEndpoint? proxy = null, string? systemProxy = null)
    {
        var result = new List<object>();
        foreach (var process in Process.GetProcessesByName("Discord"))
        {
            using (process) try
            {
                string path = process.MainModule?.FileName ?? "";
                var pin = pins.FirstOrDefault(p => string.Equals(p.Path, path, StringComparison.OrdinalIgnoreCase));
                result.Add(new { Pid = process.Id, BirthUtc = process.StartTime.ToUniversalTime(), Component = "Discord.exe",
                    PathSha256 = AionTunPlan.Hash(path), Approved = pin is not null, ImageSha256 = pin?.Sha256,
                    Decision = pin is not null ? "ExactSignedImage_UDPOnly" : "UnapprovedVersion_UnchangedDirect",
                    TcpSockets = proxy is null ? null : TcpEvidence((uint)process.Id, proxy, systemProxy) });
            }
            catch { result.Add(new { Pid = process.Id, IdentityUnavailable = true, Approved = false }); }
        }
        return result;
    }
    private static object TcpEvidence(uint pid, LocalProxyEndpoint proxy, string? systemProxy)
    {
        try
        {
            return TcpOwnership.ReadBindings(false).Concat(TcpOwnership.ReadBindings(true)).Where(b => b.ProcessId == pid).Take(128).Select(b =>
            {
                var address = b.Flow.Remote; byte[] raw = new byte[address.V6 ? 16 : 4]; BinaryPrimitives.WriteUInt32BigEndian(raw, address.A);
                if (address.V6) { BinaryPrimitives.WriteUInt32BigEndian(raw.AsSpan(4), address.B); BinaryPrimitives.WriteUInt32BigEndian(raw.AsSpan(8), address.C); BinaryPrimitives.WriteUInt32BigEndian(raw.AsSpan(12), address.D); }
                return new { State = b.State, Family = address.V6 ? "IPv6" : "IPv4", LocalPort = b.Flow.LocalPort, RemotePort = b.Flow.RemotePort,
                    TupleSha256 = AionTunPlan.Hash(System.Text.Json.JsonSerializer.Serialize(b.Flow)), Path = ClassifyPeer(new IPAddress(raw), b.Flow.RemotePort, proxy, systemProxy) };
            }).ToArray();
        }
        catch { return new { SocketTableUnavailable = true }; }
    }
    public static string ClassifyPeer(IPAddress ip, int port, LocalProxyEndpoint proxy, string? systemProxy)
    {
        if (ip.Equals(IPAddress.Parse(proxy.Host)) && port == proxy.Port) return "SelectedV2rayInput_ApplicationExplicitProxy";
        foreach (Match match in Regex.Matches(systemProxy ?? "", @"(?:^|[;=])(?<host>localhost|127\.0\.0\.1|\[::1\]):(?<port>\d{1,5})(?:;|$)"))
            if ((match.Groups["host"].Value == "localhost" ? IPAddress.IsLoopback(ip) : IPAddress.Parse(match.Groups["host"].Value.Trim('[', ']')).Equals(ip)) && int.TryParse(match.Groups["port"].Value, out int p) && port == p) return "ConfiguredSystemProxyEndpoint_ObservedSocket";
        return IPAddress.IsLoopback(ip) ? "OtherLoopback_ProxyUnproven" : "RemoteSocket_CoreFinalDirectUnlessApiShowsOtherwise";
    }
}
