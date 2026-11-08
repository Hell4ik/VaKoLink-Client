using System.Buffers.Binary;
using System.Security.Cryptography;
using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public sealed record AionFragmentSample(string FlowSha256, uint ProcessId, int? RelativeSequence, int OriginalPayloadBytes,
    int FirstTransportBytes, int SecondTransportBytes, bool PayloadPreserved, bool TcpHeaderPreservedExceptChecksum,
    bool ReassembledTcpChecksumValid, bool FirstBeforeSecondCapture);
public sealed record AionFragmentEvidence(long OriginalsStored, long FragmentCopiesStored, long MatchingFragmentPairs,
    long FirstBeforeSecondPairs, long ReassembledCopies, long UnmatchedFragmentCopies, long LimitDrops,
    IReadOnlyList<AionFragmentSample> Samples, IReadOnlyDictionary<string, long> Decisions,
    string Scope = "Selected before main PID/birth/flow originals versus two outbound IPv4 pieces, same src/dst/protocol/ID/interface, within500ms. Reassembled TCP header+payload byte-matched except checksum field; checksums verified. No payload/raw ID/addresses exported. Capture proof, not physical wire or remote reassembly.",
    IReadOnlyList<FragmentFrameObservation>? FrameObservations = null,
    IReadOnlyList<FragmentCaptureMetadata>? CaptureObservations = null, long CaptureMetadataDropped = 0, long FragmentMetadataDropped = 0);
public sealed record FragmentFrameObservation(int HeaderBytes, int IpBytes, int BodyBytes, int OffsetBytes, bool More,
    bool DontFragment, bool ReservedFlag, bool IpChecksumValid, string Decision);

// Volatile bounded clones only. No socket, Send, mutation authorization, raw ID or payload export.
public sealed class AionIpv4FragmentProof : IDisposable
{
    private sealed record Original(byte[] Bytes, TcpPacket Packet, OwnedPacket Owner, long Qpc);
    private sealed record Piece(byte[] Bytes, PacketAddress Source, PacketAddress Destination, ushort Id, uint Interface,
        int Offset, bool More, long Qpc)
    { internal bool Emitted; internal int BodyLength => Bytes.Length - 20; }
    private readonly List<Original> _originals = [];
    private readonly List<Piece> _pieces = [];
    private readonly Dictionary<(string, uint, long), uint> _origins = [];
    private readonly Dictionary<string, long> _decisions = [];
    private readonly List<FragmentFrameObservation> _frames = [];
    private readonly List<FragmentCaptureMetadata> _captures = [];
    private long _captureDrops, _fragmentCaptureDrops;
    private int _normalCaptures, _fragmentCaptures, _lastCaptureIndex = -1;
    public void RecordCapture(ReadOnlySpan<byte> bytes, DivertAddress address)
    {
        var metadata = FragmentCaptureDiagnostics.Describe(bytes, address, -30000, "AFTER_RECV_BEFORE_PARSE", true);
        lock (_gate)
        {
            if (_disposed) return;
            _lastCaptureIndex = -1;
            bool fragment = metadata.More == true || metadata.OffsetBytes > 0;
            if (fragment ? _fragmentCaptures >= 512 : _normalCaptures >= 128)
            { _captureDrops++; if (fragment) _fragmentCaptureDrops++; return; }
            if (fragment) _fragmentCaptures++; else _normalCaptures++;
            _lastCaptureIndex = _captures.Count; _captures.Add(metadata);
        }
    }
    private readonly object _gate = new(); private int _bytes; private long _drops, _reassembled; private bool _disposed;
    private void Count(string key) => _decisions[key] = _decisions.GetValueOrDefault(key) + 1;
    private void FragmentDecision(string key)
    {
        Count(key);
        if (_lastCaptureIndex >= 0) _captures[_lastCaptureIndex] = _captures[_lastCaptureIndex] with { ParserDecision = key };
    }
    public void ObserveOriginal(TcpPacket p, ReadOnlySpan<byte> bytes, OwnedPacket owner, bool outbound, long qpc)
    {
        if (!outbound || p.IsV6) return;
        lock (_gate)
        {
            if (_disposed) return;
            var key = (TcpFlowFingerprint.Flow(p.Flow), owner.Identity.ProcessId, owner.Identity.CreationTime);
            if (p.Flags == 2 && _origins.Count < 2) _origins.TryAdd(key, unchecked(p.Sequence + 1));
            if (p.PayloadLength == 0) return;
            if (_originals.Count == 256 || bytes.Length > 16384 || _bytes > 4 * 1024 * 1024 - bytes.Length)
            { _drops++; Count("ORIGINAL_LIMIT"); return; }
            var copy = bytes.ToArray(); _bytes += copy.Length; _originals.Add(new(copy, p, owner, qpc));
        }
    }
    public byte[]? ObserveFragment(ReadOnlySpan<byte> bytes, bool outbound, uint iface, long qpc, long frequency)
    {
        if (frequency <= 0) throw new ArgumentOutOfRangeException(nameof(frequency));
        lock (_gate)
        {
            if (_disposed) return null;
            if (!outbound || bytes.Length < 21 || bytes[0] != 0x45 || bytes[9] != 6
                || BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]) != bytes.Length)
            { FragmentDecision("FRAGMENT_FORMAT_OR_DIRECTION_UNSUPPORTED"); return null; }
            ushort bits = BinaryPrimitives.ReadUInt16BigEndian(bytes[6..]); int offset = (bits & 8191) * 8; bool more = (bits & 8192) != 0;
            bool checksum = InternetChecksum.Compute(bytes[..20]) == 0;
            string reason = (bits & 0xC000) != 0 ? "FRAGMENT_DF_OR_RESERVED_SET" : !more && offset == 0 ? "NOT_FRAGMENT"
                : more && (bytes.Length - 20) % 8 != 0 ? "NONFINAL_BODY_NOT_ALIGNED" : !checksum ? "IP_CHECKSUM_UNVERIFIED" : "ACCEPTED";
            if (_frames.Count < 16) _frames.Add(new(20, bytes.Length, bytes.Length - 20, offset, more, (bits & 0x4000) != 0, (bits & 0x8000) != 0, checksum, reason));
            if (reason != "ACCEPTED") { FragmentDecision(reason); return null; }
            FragmentDecision("ACCEPTED");
            if (_pieces.Count == 512 || bytes.Length > 16384 || _bytes > 4 * 1024 * 1024 - bytes.Length)
            { _drops++; Count("FRAGMENT_LIMIT"); return null; }
            var copy = bytes.ToArray(); _bytes += copy.Length;
            var piece = new Piece(copy, PacketAddress.Read(bytes[12..], false), PacketAddress.Read(bytes[16..], false),
                BinaryPrimitives.ReadUInt16BigEndian(bytes[4..]), iface, offset, more, qpc); _pieces.Add(piece);
            foreach (var head in _pieces.Where(p => !p.Emitted && p.Offset == 0 && p.More))
                foreach (var tail in _pieces.Where(p => !p.Emitted && p.Offset == head.BodyLength && !p.More && SameDatagram(head, p)
                    && Math.Abs(p.Qpc - head.Qpc) <= frequency / 2))
                {
                    var joined = Join(head, tail);
                    if (!TcpPacket.TryParse(joined, out var tcp) || tcp is null || TlsClientHelloSplit.Checksum(joined, tcp) != 0)
                    { CryptographicOperations.ZeroMemory(joined); Count("REASSEMBLY_TCP_CHECKSUM_INVALID"); continue; }
                    head.Emitted = tail.Emitted = true; _reassembled++; return joined;
                }
            return null;
        }
    }
    private static bool SameDatagram(Piece a, Piece b) => a.Source == b.Source && a.Destination == b.Destination && a.Id == b.Id && a.Interface == b.Interface;
    private static byte[] Join(Piece head, Piece tail)
    {
        var result = new byte[20 + head.BodyLength + tail.BodyLength]; head.Bytes.CopyTo(result, 0); tail.Bytes.AsSpan(20).CopyTo(result.AsSpan(head.Bytes.Length));
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2), (ushort)result.Length); result[6] = result[7] = result[10] = result[11] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(10), InternetChecksum.Compute(result.AsSpan(0, 20))); return result;
    }
    private static bool SameTransport(ReadOnlySpan<byte> original, ReadOnlySpan<byte> joined)
    {
        if (original.Length != joined.Length || original.Length < 20) return false;
        return original[..16].SequenceEqual(joined[..16]) && original[18..].SequenceEqual(joined[18..]);
    }
    public AionFragmentEvidence Snapshot(long frequency)
    {
        if (frequency <= 0) throw new ArgumentOutOfRangeException(nameof(frequency));
        lock (_gate)
        {
            var used = new HashSet<Piece>(); long matches = 0, ordered = 0; var samples = new List<AionFragmentSample>();
            foreach (var o in _originals)
            {
                bool done = false;
                foreach (var head in _pieces.Where(p => !used.Contains(p) && p.Offset == 0 && p.More && p.Source == o.Packet.Flow.Local
                    && p.Destination == o.Packet.Flow.Remote && p.Qpc >= o.Qpc && p.Qpc - o.Qpc <= frequency / 2))
                {
                    int expected = o.Packet.TotalLength - o.Packet.IpLength > 32 ? 32 : 24;
                    if (head.BodyLength != expected) continue;
                    foreach (var tail in _pieces.Where(p => !used.Contains(p) && p.Offset == expected && !p.More && SameDatagram(head, p)
                        && p.Qpc >= o.Qpc && p.Qpc - o.Qpc <= frequency / 2))
                    {
                        var joined = Join(head, tail);
                        bool valid = SameTransport(o.Bytes.AsSpan(o.Packet.IpLength), joined.AsSpan(20))
                            && TcpPacket.TryParse(joined, out var tcp) && TlsClientHelloSplit.Checksum(joined, tcp!) == 0;
                        CryptographicOperations.ZeroMemory(joined); if (!valid) continue;
                        used.Add(head); used.Add(tail); matches++; bool order = head.Qpc < tail.Qpc; if (order) ordered++;
                        var key = (TcpFlowFingerprint.Flow(o.Packet.Flow), o.Owner.Identity.ProcessId, o.Owner.Identity.CreationTime);
                        int? relative = _origins.TryGetValue(key, out var origin) ? unchecked((int)(o.Packet.Sequence - origin)) : null;
                        if (relative is < 0 or > GameTcpTracker.MaximumOffset) relative = null;
                        if (samples.Count < 32) samples.Add(new(key.Item1, key.ProcessId, relative, o.Packet.PayloadLength,
                            head.BodyLength, tail.BodyLength, true, true, true, order));
                        done = true; break;
                    }
                    if (done) break;
                }
            }
            return new(_originals.Count, _pieces.Count, matches, ordered, _reassembled, _pieces.Count - used.Count, _drops, samples, new Dictionary<string, long>(_decisions), FrameObservations: _frames.ToArray(), CaptureObservations: _captures.ToArray(), CaptureMetadataDropped: _captureDrops, FragmentMetadataDropped: _fragmentCaptureDrops);
        }
    }
    // Own-loopback fixture helper only; not installed as a production strategy.
    public static byte[][] BuildFixtureFragments(byte[] original, ushort id)
    {
        if (!TcpPacket.TryParse(original, out var tcp) || tcp is null || tcp.IsV6 || tcp.IpLength != 20 || tcp.PayloadLength == 0)
            throw new ArgumentException("FRAGMENT_FIXTURE_PACKET_INVALID");
        var source = original.ToArray(); source[36] = source[37] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(source.AsSpan(36), TlsClientHelloSplit.Checksum(source, tcp));
        int transport = source.Length - 20, split = transport > 32 ? 32 : 24;
        if (transport <= split) throw new ArgumentException("FRAGMENT_FIXTURE_TOO_SMALL");
        byte[] Part(int start, int length, bool more)
        {
            var p = new byte[20 + length]; source.AsSpan(0, 20).CopyTo(p); source.AsSpan(20 + start, length).CopyTo(p.AsSpan(20));
            BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), (ushort)p.Length); BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(4), id);
            BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(6), (ushort)((more ? 8192 : 0) | start / 8)); p[10] = p[11] = 0;
            BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10), InternetChecksum.Compute(p.AsSpan(0, 20))); return p;
        }
        var parts = new[] { Part(0, split, true), Part(split, transport - split, false) }; CryptographicOperations.ZeroMemory(source); return parts;
    }
    public void Dispose()
    { lock (_gate) { foreach (var o in _originals) CryptographicOperations.ZeroMemory(o.Bytes); foreach (var p in _pieces) CryptographicOperations.ZeroMemory(p.Bytes); _originals.Clear(); _pieces.Clear(); _disposed = true; } }
}
