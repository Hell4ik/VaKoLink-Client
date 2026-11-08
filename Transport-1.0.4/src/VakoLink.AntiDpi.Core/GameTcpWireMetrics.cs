using System.Buffers.Binary;

namespace VakoLink.AntiDpi.Core;

public sealed record GameTcpWireMetrics(int MaximumOutboundPayload, int MaximumInboundPayload, int MaximumOutboundIpBytes,
    int? LocalSynMss, int? PeerSynMss, ushort? LastPeerWindowRaw, long PeerZeroWindowCopies, long OutboundIpv4DfCopies,
    string Limitation = "Capture sizes may reflect offload or TUN/proxy client leg; not physical wire MTU. Raw TCP window is unscaled; missing SYN means MSS unobserved");

public sealed class GameTcpWireObserver
{
    private int _out, _in, _ip;
    private int? _localMss, _peerMss;
    private ushort? _window;
    private long _zeros, _df;
    public void Observe(TcpPacket packet, ReadOnlySpan<byte> bytes, bool outbound)
    {
        if (bytes.Length != packet.TotalLength || bytes.Length < packet.PayloadOffset) throw new ArgumentException("WIRE_PACKET_LENGTH_INVALID");
        if (outbound) { _out = Math.Max(_out, packet.PayloadLength); _ip = Math.Max(_ip, bytes.Length); }
        else
        {
            _in = Math.Max(_in, packet.PayloadLength); _window = BinaryPrimitives.ReadUInt16BigEndian(bytes[(packet.IpLength + 14)..]);
            if (_window == 0) _zeros++;
        }
        if (outbound && !packet.IsV6 && (BinaryPrimitives.ReadUInt16BigEndian(bytes[6..]) & 0x4000) != 0) _df++;
        if ((packet.Flags & 2) == 0) return;
        var options = bytes.Slice(packet.IpLength + 20, packet.TcpLength - 20);
        for (int at = 0; at < options.Length;)
        {
            byte kind = options[at]; if (kind == 0) break; if (kind == 1) { at++; continue; }
            if (at + 2 > options.Length || options[at + 1] < 2 || at + options[at + 1] > options.Length) break;
            if (kind == 2 && options[at + 1] == 4)
            {
                int value = BinaryPrimitives.ReadUInt16BigEndian(options[(at + 2)..]);
                if (value > 0) { if (outbound) _localMss ??= value; else _peerMss ??= value; }
            }
            at += options[at + 1];
        }
    }
    public GameTcpWireMetrics Snapshot() => new(_out, _in, _ip, _localMss, _peerMss, _window, _zeros, _df);
}
