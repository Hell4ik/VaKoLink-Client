using System.Buffers.Binary;
using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

// Metadata only, recorded BEFORE transport parsing. Never exports addresses, IP IDs, handles or payload.
public sealed record FragmentCaptureMetadata(int CapturedBytes, int? DeclaredIpBytes, int? HeaderBytes,
    int? BodyBytes, int? OffsetBytes, bool? More, bool? DontFragment, bool? ReservedFlag,
    bool Outbound, bool Loopback, bool Impostor, bool NativeIpChecksum, bool NativeTcpChecksum,
    bool NativeUdpChecksum, int? ComputedIpChecksumResidual, string ChecksumStatus, bool? ExactFilterMatched,
    short Priority, string Stage, string? ParserDecision = null, bool? IpChecksumFieldZero = null);

public static class FragmentCaptureDiagnostics
{
    public static FragmentCaptureMetadata Describe(ReadOnlySpan<byte> b, DivertAddress a, short priority, string stage, bool? exact = null)
    {
        int? header = b.Length > 0 && b[0] >> 4 == 4 ? (b[0] & 15) * 4 : null;
        int? length = header is not null && b.Length >= 4 ? BinaryPrimitives.ReadUInt16BigEndian(b[2..]) : null;
        int? flags = header is not null && b.Length >= 8 ? BinaryPrimitives.ReadUInt16BigEndian(b[6..]) : null;
        int? checksum = header is >= 20 and <= 60 && b.Length >= header ? InternetChecksum.Compute(b[..header.Value]) : null;
        bool native = (a.Bits & (1u << 21)) != 0;
        return new(b.Length, length, header, header is not null && b.Length >= header ? b.Length - header : null,
            flags is null ? null : (flags & 8191) * 8, flags is null ? null : (flags & 8192) != 0,
            flags is null ? null : (flags & 16384) != 0, flags is null ? null : (flags & 32768) != 0,
            a.Outbound, (a.Bits & (1u << 18)) != 0, a.Impostor, native, (a.Bits & (1u << 22)) != 0,
            (a.Bits & (1u << 23)) != 0, checksum,
            checksum is null ? "HEADER_UNAVAILABLE" : checksum == 0 ? "BYTES_VALID" : native ? "NATIVE_BYTES_DISAGREE" : "OFFLOAD_OR_UNVERIFIED",
            exact, priority, stage, IpChecksumFieldZero: header is not null && b.Length >= 12 ? BinaryPrimitives.ReadUInt16BigEndian(b[10..]) == 0 : null);
    }
}

public sealed record FragmentAuditEvidence(int Opened, int Closed, bool DllUnloaded, long Received, long MetadataDropped,
    string? Failure, IReadOnlyList<FragmentCaptureMetadata> Frames,
    string Scope = "Diagnostic localhost only; NETWORK SNIFF RECV_ONLY priority -29999, broad IPv4 protocol6 filter. Metadata retained for own ephemeral port and ALL fragments before parsing; unrelated complete localhost packets counted but not retained. Exact AFTER filter evaluated on received bytes; no Send API, no game/wire claim.",
    long FirstFragmentsReceived = 0, long TailFragmentsReceived = 0, long FragmentFilterRejected = 0, long OtherCompleteLocalPackets = 0);

internal sealed class FragmentLoopbackAudit : IAsyncDisposable
{
    private readonly WinDivertLibrary _library;
    private readonly string _exact;
    private readonly ushort _port;
    private readonly object _gate = new();
    private readonly List<FragmentCaptureMetadata> _frames = [];
    private readonly Task _worker;
    private readonly IntPtr _handle;
    private volatile bool _stopping;
    private int _closed; private bool _unloaded; private long _received, _dropped, _first, _tails, _rejected, _other; private string? _failure;
    internal FragmentAuditEvidence Evidence { get { lock (_gate) return new(1, _closed, _unloaded, _received, _dropped, _failure, _frames.ToArray(), FirstFragmentsReceived: _first, TailFragmentsReceived: _tails, FragmentFilterRejected: _rejected, OtherCompleteLocalPackets: _other); } }
    internal FragmentLoopbackAudit(string engine, ushort port)
    {
        _port = port; _exact = AionZapretResearchPlan.FragmentObservationFilter("127.0.0.1", port, true);
        _library = new(Path.Combine(engine, "WinDivert.dll"));
        _handle = _library.Open("loopback and ip and ip.Protocol == 6 and ip.SrcAddr == 127.0.0.1 and ip.DstAddr == 127.0.0.1", 0, -29999, 5);
        if (_handle == IntPtr.Zero || _handle == new IntPtr(-1)) { _library.Dispose(); throw new InvalidOperationException("FRAGMENT_AUDIT_OPEN_FAILED"); }
        _worker = Task.Factory.StartNew(Run, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    }
    private void Run()
    {
        var buffer = new byte[65535];
        try
        {
            while (_library.Recv(_handle, buffer, (uint)buffer.Length, out var size, out var address))
            {
                bool exact = _library.Eval(_exact, buffer, size, ref address);
                var bytes = buffer.AsSpan(0, checked((int)size));
                var metadata = FragmentCaptureDiagnostics.Describe(bytes, address, -29999, "BROAD_RECV_BEFORE_PARSE", exact);
                bool fragment = metadata.More == true || metadata.OffsetBytes > 0;
                bool portMatches = metadata.HeaderBytes is >= 20 and <= 60 && bytes.Length >= metadata.HeaderBytes + 4
                    && (BinaryPrimitives.ReadUInt16BigEndian(bytes[metadata.HeaderBytes.Value..]) == _port
                        || BinaryPrimitives.ReadUInt16BigEndian(bytes[(metadata.HeaderBytes.Value + 2)..]) == _port);
                lock (_gate)
                {
                    _received++;
                    if (fragment) { if (metadata.OffsetBytes == 0) _first++; else _tails++; if (!exact) _rejected++; }
                    if (!fragment && !portMatches) { _other++; continue; }
                    if (_frames.Count < 128) _frames.Add(metadata); else _dropped++;
                }
            }
            if (!_stopping) _failure = "FRAGMENT_AUDIT_RECEIVE_FAILED";
        }
        catch (Exception ex) { _failure = "FRAGMENT_AUDIT_" + ex.GetType().Name; }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(buffer); }
    }
    public async ValueTask DisposeAsync()
    {
        if (_unloaded) return;
        _stopping = true;
        if (!_library.Shutdown(_handle, 1)) _failure ??= "FRAGMENT_AUDIT_SHUTDOWN_FAILED";
        await _worker.WaitAsync(TimeSpan.FromSeconds(5));
        if (!_library.Close(_handle)) throw new InvalidOperationException("FRAGMENT_AUDIT_CLOSE_FAILED");
        _closed = 1; _library.Dispose(); _unloaded = true;
    }
}
