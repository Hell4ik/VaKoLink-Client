using System.Net;
using System.Security.Cryptography;
using System.Text;
using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public sealed record ReferenceInput(string File, long Bytes, string Sha256);
public sealed record ReferenceRule(int Index, IReadOnlyList<string> Arguments);
public sealed record ReferenceHostMembership(string Host, string File, bool Matches);
public sealed record ReferenceConfigurationEvidence(string Source, string BatSha256, string NormalizedArgvSha256,
    IReadOnlyList<string> Arguments, IReadOnlyList<ReferenceRule> Rules, IReadOnlyList<ReferenceInput> Inputs,
    string TimestampPrerequisite = "BAT calls tcp_enable; this program never changes system timestamps. Actual data-packet TS is checked separately.",
    string InputsBasis = "Current file hashes; attached process may have loaded lists earlier. Not proof of historical engine file reads.",
    IReadOnlyList<ReferenceHostMembership>? PublicHostMembership = null);
public sealed record ReferenceFlowDecision(string FlowSha256, string RemoteAddressSha256, ushort RemotePort,
    int? FirstMatchingRule, string Decision, string? Mechanism, string? KnownHost, string AddressFamily);

// Data-only projection. First matching rule, list unions/exclusions and duplicate fake options preserved.
// Not proof winws executed a desync; passive wire copies and client outcome are separate evidence.
public sealed class ReferenceConfiguration
{
    private readonly string _root; private readonly IReadOnlyList<string> _arguments;
    private readonly Dictionary<string, string[]> _lists = new(StringComparer.OrdinalIgnoreCase);
    public ReferenceConfigurationEvidence Evidence { get; }
    internal ReferenceConfiguration(string root, IReadOnlyList<string> arguments, string batHash, string source)
    {
        _root = Path.GetFullPath(root); _arguments = arguments;
        var normalized = arguments.Select(Normalize).ToArray();
        var rules = new List<ReferenceRule>(); var current = new List<string>();
        foreach (var arg in normalized) { if (arg == "--new") { rules.Add(new(rules.Count + 1, current.ToArray())); current.Clear(); } else current.Add(arg); }
        rules.Add(new(rules.Count + 1, current.ToArray()));
        var inputs = new List<ReferenceInput>();
        foreach (var path in arguments.Where(arg => arg.Contains('=')).Select(arg => arg[(arg.IndexOf('=') + 1)..]).Where(Path.IsPathFullyQualified).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var full = Path.GetFullPath(path);
            if (!full.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("REFERENCE_INPUT_OUTSIDE_ROOT");
            var info = new FileInfo(full); if (info.Length > 16_000_000 || info.Attributes.HasFlag(FileAttributes.ReparsePoint)) throw new InvalidDataException("REFERENCE_INPUT_INVALID");
            inputs.Add(new(Path.GetRelativePath(_root, full).Replace('\\', '/'), info.Length, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(full)))));
            if (Path.GetExtension(full).Equals(".txt", StringComparison.OrdinalIgnoreCase))
                _lists[full] = File.ReadAllLines(full).Select(line => line.Split('#')[0].Trim().ToLowerInvariant()).Where(line => line.Length > 0).ToArray();
        }
        var flag = Path.Combine(root, "utils", "game_filter.enabled");
        if (File.Exists(flag))
        {
            var info = new FileInfo(flag);
            if (info.Length > 1024 || info.Attributes.HasFlag(FileAttributes.ReparsePoint)) throw new InvalidDataException("REFERENCE_GAME_FLAG_INVALID");
            inputs.Add(new("utils/game_filter.enabled", info.Length, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(flag)))));
        }
        var membership = (from host in new[] { "discord.com", "updates.discord.com", "cloudflare-ech.com", "discord.media", "gateway.discord.gg" }
                          from list in _lists.Where(pair => Path.GetFileName(pair.Key).StartsWith("list-", StringComparison.Ordinal))
                          select new ReferenceHostMembership(host, Path.GetRelativePath(root, list.Key).Replace('\\', '/'), list.Value.Any(entry => HostMatches(host, entry)))).ToArray();
        Evidence = new(source, batHash, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', normalized)))), normalized, rules, inputs,
            InputsBasis: source == "OWNED_ACTUAL_LAUNCH_ARGV" ? "Inputs locked and hashed before owned process start." : "Current file hashes; attached process may have loaded lists earlier. Not proof of historical engine file reads.",
            PublicHostMembership: membership);
    }
    public static ReferenceConfiguration Read(string engineDirectory, string source = "RESOLVED_CURRENT_BAT_NOT_HISTORICAL_PROCESS")
    {
        var root = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(Path.GetFullPath(engineDirectory)))!;
        var bat = Path.Combine(root, "general (ALT13).bat"); var bytes = File.ReadAllBytes(bat); var hash = Convert.ToHexString(SHA256.HashData(bytes));
        if (hash != OriginalZapretReference.PinnedAlt13Sha256) throw new InvalidDataException("ALT13_CONFIGURATION_CHANGED_REAUDIT_REQUIRED");
        var flag = Path.Combine(root, "utils", "game_filter.enabled");
        return new(root, OriginalZapretReference.ParseArguments(File.ReadAllText(bat), root, File.Exists(flag) ? File.ReadAllText(flag) : null), hash, source);
    }
    private string Normalize(string argument)
    {
        var at = argument.IndexOf('='); if (at < 0) return argument; var value = argument[(at + 1)..];
        return Path.IsPathFullyQualified(value) ? argument[..(at + 1)] + "[ROOT]/" + Path.GetRelativePath(_root, value).Replace('\\', '/') : argument;
    }
    internal IReadOnlyList<string> ActualArguments => _arguments;
    internal IEnumerable<string> HostList(string fileName) => _lists.Where(pair => Path.GetFileName(pair.Key) == fileName).SelectMany(pair => pair.Value);
    public ReferenceFlowDecision Evaluate(TcpFlow flow, TlsSniEvidence? sni) => Evaluate(flow, sni, null);
    internal ReferenceFlowDecision Evaluate(TcpFlow flow, TlsSniEvidence? sni, string? ephemeralHost)
    {
        if (ephemeralHost is null && sni?.KnownHost == "REDACTED")
            return new(TcpFlowFingerprint.Flow(flow), TcpFlowFingerprint.RemoteAddress(flow), flow.RemotePort, null,
                "PROJECTION_INCOMPLETE_REDACTED_HOST", null, sni.KnownHost, flow.Local.V6 ? "IPv6" : "IPv4");
        string? host = ephemeralHost ?? (sni?.KnownHost is not (null or "REDACTED") ? sni.KnownHost : sni?.Root is not (null or "OTHER") ? sni.Root : null);
        var rules = new List<List<string>> { new() };
        foreach (var arg in _arguments) { if (arg == "--new") rules.Add(new()); else rules[^1].Add(arg); }
        for (int i = 0; i < rules.Count; i++)
        {
            var rule = rules[i]; string[] Values(string key) => rule.Where(arg => arg.StartsWith("--" + key + "=", StringComparison.Ordinal)).Select(arg => arg[(key.Length + 3)..]).ToArray();
            if (Values("filter-udp").Length > 0 || !Values("filter-tcp").Any(ports => InPorts(flow.RemotePort, ports))) continue;
            bool Hosts(string key) => Values(key).Any(path => _lists.GetValueOrDefault(path, []).Any(entry => HostMatches(host, entry)));
            bool Ips(string key) => Values(key).Any(path => _lists.GetValueOrDefault(path, []).Any(entry => InCidr(flow.Remote, entry)));
            if (Hosts("hostlist-exclude") || Ips("ipset-exclude")) continue;
            if (Values("hostlist").Length > 0 && !Hosts("hostlist")) continue;
            if (Values("hostlist-domains").Length > 0 && !Values("hostlist-domains").SelectMany(value => value.Split(',')).Any(entry => HostMatches(host, entry))) continue;
            if (Values("ipset").Length > 0 && !Ips("ipset")) continue;
            return new(TcpFlowFingerprint.Flow(flow), TcpFlowFingerprint.RemoteAddress(flow), flow.RemotePort, i + 1,
                "FIRST_STATIC_RULE_MATCH_NOT_EXECUTION_PROOF", Values("dpi-desync").FirstOrDefault(), sni?.KnownHost, flow.Local.V6 ? "IPv6" : "IPv4");
        }
        return new(TcpFlowFingerprint.Flow(flow), TcpFlowFingerprint.RemoteAddress(flow), flow.RemotePort, null,
            host is null ? "NO_MATCH_HOST_UNKNOWN" : "NO_STATIC_RULE_MATCH", null, sni?.KnownHost, flow.Local.V6 ? "IPv6" : "IPv4");
    }
    internal static bool HostMatches(string? host, string entry) => host is not null && (host.Equals(entry, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + entry, StringComparison.OrdinalIgnoreCase));
    internal static bool InPorts(ushort port, string ports) => ports.Split(',').Any(piece =>
    {
        var parts = piece.Split('-'); return ushort.TryParse(parts[0], out var start) && (parts.Length == 1 ? port == start : parts.Length == 2 && ushort.TryParse(parts[1], out var end) && port >= start && port <= end);
    });
    internal static bool InCidr(PacketAddress address, string text)
    {
        var parts = text.Split('/'); if (!IPAddress.TryParse(parts[0], out var ip)) return false;
        var network = ip.GetAddressBytes(); var actual = TcpFlowFingerprint.AddressBytes(address); if (network.Length != actual.Length) return false;
        int bits = network.Length * 8; if (parts.Length > 2 || parts.Length == 2 && (!int.TryParse(parts[1], out bits) || bits < 0 || bits > network.Length * 8)) return false;
        for (int at = 0; at < network.Length; at++) { int take = Math.Clamp(bits - at * 8, 0, 8); int mask = 0xff << (8 - take) & 0xff; if ((network[at] & mask) != (actual[at] & mask)) return false; }
        return true;
    }
}
