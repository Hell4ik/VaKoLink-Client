using System.Buffers.Binary;
using System.Net;

namespace VakoLink.AntiDpi.Windows;

public sealed record FragmentFilterEvidence(bool Compiled, bool FirstSelected, bool TailSelected, bool OtherAddressExcluded,
    bool UdpExcluded, bool InboundOtherPortExcluded, string Scope = "Passive after-observer only: outbound TCP fragments at exact remote IPv4 address, tails have no ports. Selected main flow attribution only after bounded reassembly. Active engine filter is unchanged exact TCP13328.")
{ public bool Passed => Compiled && FirstSelected && TailSelected && OtherAddressExcluded && UdpExcluded && InboundOtherPortExcluded; }

public sealed record ResearchFilterEvidence(bool Compiled, bool SelectedOutbound, bool SelectedInbound, bool OtherAddressExcluded,
    bool OtherPortExcluded, bool UdpExcluded, bool Ipv6Excluded, bool LoopbackExcluded, bool ImpostorExcluded,
    int NativeHandlesOpened = 0, int PacketsSent = 0)
{
    public bool Passed => Compiled && SelectedOutbound && SelectedInbound && OtherAddressExcluded && OtherPortExcluded
        && UdpExcluded && Ipv6Excluded && LoopbackExcluded && ImpostorExcluded && NativeHandlesOpened == 0 && PacketsSent == 0;
}
public static class ResearchFilterVerification
{
    public static FragmentFilterEvidence VerifyFragments(string engine, string target, ushort port, bool loopback)
    {
        RuntimePreflight.VerifyPackage(engine, CancellationToken.None);
        using var library = new WinDivertLibrary(Path.Combine(engine, "WinDivert.dll"));
        var filter = AionZapretResearchPlan.FragmentObservationFilter(target, port, loopback);
        bool Check(byte[] b, bool outgoing = true)
        { var a = new DivertAddress { Bits = (outgoing ? 1u << 17 : 0) | (loopback ? 1u << 18 : 0) }; return library.Eval(filter, b, (uint)b.Length, ref a); }
        var b = Packet(target, port, true); Array.Resize(ref b, 51); BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(2), (ushort)b.Length);
        var parts = AionIpv4FragmentProof.BuildFixtureFragments(b, 1);
        var wrong = parts[1].ToArray(); wrong[19] ^= 1;
        var udp = parts[1].ToArray(); udp[9] = 17;
        return new(library.Compile(filter, 0, IntPtr.Zero, 0, out _, out _), Check(parts[0]), Check(parts[1]), !Check(wrong), !Check(udp), !Check(Packet(target, (ushort)(port + 1), false), false));
    }
    public static ResearchFilterEvidence Verify(string engine, string target)
    {
        if (!AionZapretResearchPlan.IsPinnedAddress(target)) throw new ArgumentException("RESEARCH_TARGET_HASH_MISMATCH");
        return VerifyCore(engine, target);
    }
    public static ResearchFilterEvidence VerifyReservedSyntheticTarget(string engine) => VerifyCore(engine, "198.51.100.2");
    private static ResearchFilterEvidence VerifyCore(string engine, string target)
    {
        RuntimePreflight.VerifyPackage(engine, CancellationToken.None);
        using var library = new WinDivertLibrary(Path.Combine(engine, "WinDivert.dll"));
        var filter = AionZapretResearchPlan.RawFilter(target, 13328);
        bool compiled = library.Compile(filter, 0, IntPtr.Zero, 0, out _, out _);
        bool Check(byte[] packet, bool outbound, bool loopback = false, bool impostor = false)
        {
            var a = new DivertAddress { Bits = (outbound ? 1u << 17 : 0) | (loopback ? 1u << 18 : 0) | (impostor ? 1u << 19 : 0) | (packet[0] >> 4 == 6 ? 1u << 20 : 0) };
            return library.Eval(filter, packet, (uint)packet.Length, ref a);
        }
        var outgoing = Packet(target, 13328, true); var incoming = Packet(target, 13328, false);
        return new(compiled, Check(outgoing, true), Check(incoming, false),
            !Check(Packet("203.0.113.3", 13328, true), true), !Check(Packet(target, 13329, true), true),
            !Check(Packet(target, 13328, true, udp: true), true), !Check(Packet(target, 13328, true, v6: true), true),
            !Check(outgoing, true, loopback: true), !Check(outgoing, true, impostor: true));
    }
    private static byte[] Packet(string target, ushort port, bool outbound, bool udp = false, bool v6 = false)
    {
        int ip = v6 ? 40 : 20; var b = new byte[ip + (udp ? 8 : 20)]; b[0] = v6 ? (byte)0x60 : (byte)0x45;
        if (v6) { BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(4), 20); b[6] = 6; b[7] = 64; }
        else
        {
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(2), (ushort)b.Length); b[8] = 64; b[9] = udp ? (byte)17 : (byte)6;
            IPAddress.Parse(outbound ? "192.0.2.1" : target).GetAddressBytes().CopyTo(b, 12);
            IPAddress.Parse(outbound ? target : "192.0.2.1").GetAddressBytes().CopyTo(b, 16);
        }
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(ip), outbound ? (ushort)50000 : port);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(ip + 2), outbound ? port : (ushort)50000);
        if (udp) BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(ip + 4), 8); else { b[ip + 12] = 0x50; b[ip + 13] = 16; }
        return b;
    }
}
