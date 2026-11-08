using System.Buffers.Binary;
using System.Net;

namespace VakoLink.AntiDpi.Windows;

public sealed record AionSynFilterEvidence(bool ActiveCompiled, bool AfterCompiled, bool InitialSynSelected, bool SynAckNotIntercepted,
    bool DataNotIntercepted, bool OtherAddressExcluded, bool OtherPortExcluded, bool UdpExcluded, bool Ipv6Excluded, bool LoopbackExcluded,
    bool ImpostorExcluded, bool IncomingSynAckObserved, bool PayloadObserved, bool InvalidFilterRejected,
    int NativeHandlesOpened = 0, int PacketsSent = 0, bool DllUnloaded = true)
{
    public bool Passed => ActiveCompiled && AfterCompiled && InitialSynSelected && SynAckNotIntercepted && DataNotIntercepted && OtherAddressExcluded
        && OtherPortExcluded && UdpExcluded && Ipv6Excluded && LoopbackExcluded && ImpostorExcluded && IncomingSynAckObserved && PayloadObserved && InvalidFilterRejected && NativeHandlesOpened == 0 && PacketsSent == 0 && DllUnloaded;
}
public static class AionSynFilterVerification
{
    public static (string Active, string After) Filters(string address, bool fixture = false)
    {
        if (!IPAddress.TryParse(address, out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) throw new ArgumentException("SYN_FILTER_IPV4_REQUIRED");
        string location = fixture ? "loopback" : "!loopback";
        string outgoing = $"outbound and ip.DstAddr == {address} and tcp.DstPort == 13328";
        string incoming = $"inbound and ip.SrcAddr == {address} and tcp.SrcPort == 13328";
        return ($"ip and tcp and {location} and {outgoing} and tcp.Syn and !tcp.Ack and !impostor",
            $"ip and tcp and {location} and (({outgoing}) or ({incoming})) and (tcp.Syn or tcp.PayloadLength > 0)");
    }
    public static AionSynFilterEvidence Verify(string engine)
    {
        RuntimePreflight.VerifyPackage(engine, CancellationToken.None);
        using var library = new WinDivertLibrary(Path.Combine(engine, "WinDivert.dll"));
        var (active, after) = Filters("203.0.113.2");
        bool Eval(string filter, byte[] bytes, bool outgoing = true, bool loopback = false, bool impostor = false)
        { var a = new DivertAddress { Bits = (outgoing ? 1u << 17 : 0) | (loopback ? 1u << 18 : 0) | (impostor ? 1u << 19 : 0) | (bytes[0] >> 4 == 6 ? 1u << 20 : 0) }; return library.Eval(filter, bytes, (uint)bytes.Length, ref a); }
        byte[] Packet(string target = "203.0.113.2", ushort port = 13328, bool outgoing = true, byte flags = 2, int payload = 0, bool udp = false, bool ipv6 = false)
        {
            int ip = ipv6 ? 40 : 20; var b = new byte[ip + (udp ? 8 : 20) + payload]; b[0] = ipv6 ? (byte)0x60 : (byte)0x45;
            if (ipv6) { b[6] = 6; BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(4), (ushort)(b.Length - 40)); }
            else { b[9] = udp ? (byte)17 : (byte)6; BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(2), (ushort)b.Length); IPAddress.Parse(outgoing ? "192.0.2.1" : target).GetAddressBytes().CopyTo(b, 12); IPAddress.Parse(outgoing ? target : "192.0.2.1").GetAddressBytes().CopyTo(b, 16); }
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(ip), outgoing ? (ushort)50000 : port); BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(ip + 2), outgoing ? port : (ushort)50000);
            if (udp) BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(ip + 4), 8); else { b[ip + 12] = 0x50; b[ip + 13] = flags; }
            return b;
        }
        return new(library.Compile(active, 0, IntPtr.Zero, 0, out _, out _), library.Compile(after, 0, IntPtr.Zero, 0, out _, out _),
            Eval(active, Packet()), !Eval(active, Packet(flags: 18)), !Eval(active, Packet(flags: 24, payload: 11)),
            !Eval(active, Packet(target: "203.0.113.3")), !Eval(active, Packet(port: 13329)), !Eval(active, Packet(udp: true)), !Eval(active, Packet(ipv6: true)),
            !Eval(active, Packet(), loopback: true), !Eval(active, Packet(), impostor: true), Eval(after, Packet(outgoing: false, flags: 18), false),
            Eval(after, Packet(flags: 24, payload: 11)), !library.Compile("tcp..Syn", 0, IntPtr.Zero, 0, out _, out _));
    }
}
