using System.Net;
using System.Security.Cryptography;
using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public enum AionOriginalCandidate { C1Multidisorder, C2FakeBadseq, C3Ipfrag2 }

public static class AionZapretResearchPlan
{
    public const string Candidate = "winws-aion-multidisorder-pos1-d192";
    public const string Version = "0.4.13-aion-original-reference-preview1";
    public const string C2Candidate = "winws-aion-fake-badseq-unknown12-d192";
    public const string C2Version = "0.4.14-aion-original-c2-preview1";
    public const string C3Candidate = "winws-aion-ipfrag2-pos32-d192";
    public const string C3Version = "0.4.15-aion-original-c3-preview1";
    public const int FakeBytes = 12, FakeSequenceDelta = -10000, FakeAckDelta = -66000;
    public const string EngineScope = "Original winws exact target IPv4 TCP13328; NOT process-bound; external native-handle counts not measured";
    public const int MaximumCandidates = 3, DataPacketCutoff = 192;
    public static IReadOnlyList<string> ReservedMechanisms => ["multidisorder", "fake+badseq", "ipfrag2"];
    public static IReadOnlyList<string> ReadOnlyFalseFilterArguments => BuildArguments("false");
    public static string CandidateId(AionOriginalCandidate candidate) => candidate switch
    { AionOriginalCandidate.C1Multidisorder => Candidate, AionOriginalCandidate.C2FakeBadseq => C2Candidate, AionOriginalCandidate.C3Ipfrag2 => C3Candidate, _ => throw new ArgumentOutOfRangeException(nameof(candidate)) };
    public static AionOriginalCandidate ParseCandidate(string id) => id switch
    { Candidate => AionOriginalCandidate.C1Multidisorder, C2Candidate => AionOriginalCandidate.C2FakeBadseq, C3Candidate => AionOriginalCandidate.C3Ipfrag2, _ => throw new ArgumentException("RESEARCH_CANDIDATE_INVALID") };
    internal static string FragmentObservationFilter(string address, ushort port, bool loopback = false)
    {
        _ = RawFilter(address, port, loopback);
        return $"ip and ip.Protocol == 6 and {(loopback ? "loopback" : "!loopback")} and ((outbound and ip.DstAddr == {address} and (tcp.DstPort == {port} or fragment)) or (inbound and ip.SrcAddr == {address} and tcp.SrcPort == {port}))";
    }
    public static bool IsPinnedAddress(string address) => IPAddress.TryParse(address, out var ip)
        && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
        && Convert.ToHexString(SHA256.HashData(ip.GetAddressBytes())) == AionTcpSegmentation.TargetAddressSha256;
    internal static string RawFilter(string address, ushort port, bool loopback = false)
    {
        if (!IPAddress.TryParse(address, out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || port == 0)
            throw new ArgumentException("RESEARCH_TARGET_INVALID");
        return $"ip and tcp and {(loopback ? "loopback" : "!loopback")} and !impostor and ((outbound and ip.DstAddr == {ip} and tcp.DstPort == {port}) or (inbound and ip.SrcAddr == {ip} and tcp.SrcPort == {port}))";
    }
    public static IReadOnlyList<string> Arguments(string address, AionOriginalCandidate candidate = AionOriginalCandidate.C1Multidisorder)
    {
        if (!IsPinnedAddress(address)) throw new ArgumentException("RESEARCH_TARGET_HASH_MISMATCH");
        return BuildArguments(RawFilter(address, AionTcpSegmentation.TargetPort), candidate);
    }
    public static IReadOnlyList<string> BuildArguments(string filter, AionOriginalCandidate candidate = AionOriginalCandidate.C1Multidisorder) => candidate switch
    {
        AionOriginalCandidate.C1Multidisorder => ["--wf-raw=" + filter, "--filter-l3=ipv4", "--filter-tcp=13328", "--dpi-desync=multidisorder",
            "--dpi-desync-any-protocol=1", "--dpi-desync-split-pos=1", "--dpi-desync-cutoff=d192", "--debug=0"],
        AionOriginalCandidate.C2FakeBadseq => ["--wf-raw=" + filter, "--filter-l3=ipv4", "--filter-tcp=13328", "--filter-l7=unknown",
            "--dpi-desync=fake", "--dpi-desync-any-protocol=1", "--dpi-desync-fooling=badseq", "--dpi-desync-badseq-increment=-10000",
            "--dpi-desync-badack-increment=-66000", "--dpi-desync-fake-unknown=0x000000000000000000000000",
            "--dpi-desync-fake-tcp-mod=none", "--dpi-desync-repeats=1", "--dpi-desync-cutoff=d192", "--debug=0"],
        AionOriginalCandidate.C3Ipfrag2 => ["--wf-raw=" + filter, "--filter-l3=ipv4", "--filter-tcp=13328", "--dpi-desync=ipfrag2",
            "--dpi-desync-any-protocol=1", "--dpi-desync-ipfrag-pos-tcp=32", "--dpi-desync-cutoff=d192", "--debug=0"],
        _ => throw new ArgumentOutOfRangeException(nameof(candidate))
    };
    public static string? DiscoverTarget(AppProfile main)
    {
        if (Path.GetFileName(main.ExecutablePath) != "AION2.exe")
            throw new InvalidOperationException("RESEARCH_AION_IMAGE_UNCONFIRMED");
        foreach (var b in TcpOwnership.ReadBindings(false).Where(b => b.Flow.RemotePort == AionTcpSegmentation.TargetPort
            && TcpFlowFingerprint.RemoteAddress(b.Flow) == AionTcpSegmentation.TargetAddressSha256 && b.State is >= 3 and <= 5))
        {
            var identity = ProcessOwnership.ReadIdentity(b.ProcessId);
            if (identity is null || OwnershipPolicy.MatchImage([main], identity) is null
                || TcpOwnership.UniqueOwner(TcpOwnership.ReadBindings(false), b.Flow) != b.ProcessId) continue;
            if (!GameComponentTrust.IsSignedNcImage(main.ExecutablePath) || ProfileBindingCollector.HashImage(main).Sha256 != AionTcpSegmentation.ClientImageSha256)
                throw new InvalidOperationException("RESEARCH_AION_IMAGE_UNCONFIRMED");
            var again = ProcessOwnership.ReadIdentity(b.ProcessId);
            if (again is not null && OwnershipPolicy.SameIdentity(identity, again)) return new IPAddress(TcpFlowFingerprint.AddressBytes(b.Flow.Remote)).ToString();
        }
        return null;
    }
}
