using System.Diagnostics;
using System.Security.Cryptography;
using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public sealed record FragmentFixtureEvidence(int Opened, int Closed, bool DllUnloaded, long OriginalsFragmented,
    long FragmentsSent, string? Failure, bool LoopbackOnly = true,
    IReadOnlyList<FragmentTransmission>? Transmissions = null, FragmentAuditEvidence? Audit = null);
public sealed record FragmentTransmission(int Ordinal, FragmentCaptureMetadata Metadata, bool SendSucceeded, int AcceptedBytes);

// Isolated diagnostic, NEVER a production backend. Only our own current PID/birth's localhost connection.
internal sealed class AionFragmentLoopbackDivert : IAsyncDisposable
{
    private readonly WinDivertLibrary _library;
    private readonly GamePassiveTrace _before;
    private readonly ProcessIdentity _own;
    private readonly Task _worker;
    private IntPtr _handle; private volatile bool _stopping;
    private int _closed; private bool _unloaded; private long _originals, _sent; private string? _failure;
    private readonly List<FragmentTransmission> _transmissions = [];
    private readonly object _gate = new();
    private readonly string _afterFilter;
    internal FragmentFixtureEvidence Evidence { get { lock (_gate) return new(1, _closed, _unloaded, _originals, _sent, _failure, Transmissions: _transmissions.ToArray()); } }
    internal AionFragmentLoopbackDivert(string engine, ushort port, GamePassiveTrace before)
    {
        _before = before; _own = ProcessOwnership.ReadIdentity((uint)Environment.ProcessId) ?? throw new InvalidOperationException("OWN_FIXTURE_IDENTITY_REQUIRED");
        _afterFilter = AionZapretResearchPlan.FragmentObservationFilter("127.0.0.1", port, true);
        _library = new(Path.Combine(engine, "WinDivert.dll"));
        _handle = _library.Open($"ip and tcp and loopback and outbound and !impostor and tcp.DstPort == {port}", 0, -100, 0);
        if (_handle == IntPtr.Zero || _handle == new IntPtr(-1)) { _library.Dispose(); throw new InvalidOperationException("FRAGMENT_FIXTURE_OPEN_FAILED"); }
        _worker = Task.Factory.StartNew(Run, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    }
    private void Run()
    {
        var buffer = new byte[65535]; ushort id = 1;
        try
        {
            while (_library.Recv(_handle, buffer, (uint)buffer.Length, out var count, out var address))
            {
                var original = buffer.AsSpan(0, (int)count).ToArray(); bool replaced = false;
                try
                {
                    if (!_stopping && _failure is null && _originals < 4 && TcpPacket.TryParse(original, out var p) && p is { IsV6: false, PayloadLength: 11 }
                        && address.Outbound && (address.Bits & (1u << 18)) != 0)
                    {
                        var owner = _before.ResolveTcp(p.Flow, address.Timestamp, false);
                        if (owner is not null && OwnershipPolicy.SameIdentity(owner.Identity, _own))
                        {
                            var parts = AionIpv4FragmentProof.BuildFixtureFragments(original, id++);
                            try
                            {
                                bool all = true;
                                var fragmentAddress = address;
                                // Fixture builder computed IPv4 and whole-datagram TCP checksums.
                                // Never reuse capture offload state to describe newly constructed packets.
                                fragmentAddress.Bits |= (1u << 21) | (1u << 22);
                                foreach (var part in parts)
                                {
                                    bool matches = _library.Eval(_afterFilter, part, (uint)part.Length, ref fragmentAddress);
                                    var metadata = FragmentCaptureDiagnostics.Describe(part, fragmentAddress, -100, "FIXTURE_BEFORE_SEND", matches);
                                    bool sent = _library.Send(_handle, part, (uint)part.Length, out var n, ref fragmentAddress);
                                    lock (_gate) _transmissions.Add(new(_transmissions.Count + 1, metadata, sent, (int)n));
                                    if (sent && n == part.Length) _sent++;
                                    else { all = false; _failure = "LOCAL_FRAGMENT_SEND_UNCONFIRMED"; break; }
                                }
                                if (all) { _originals++; replaced = true; }
                            }
                            finally { foreach (var part in parts) CryptographicOperations.ZeroMemory(part); }
                        }
                    }
                }
                catch (Exception ex) { _failure ??= "LOCAL_FRAGMENT_" + ex.GetType().Name; }
                finally
                {
                    if (!replaced && (!_library.Send(_handle, original, (uint)original.Length, out var sent, ref address) || sent != original.Length))
                        _failure ??= "LOCAL_ORIGINAL_FORWARD_UNCONFIRMED";
                    CryptographicOperations.ZeroMemory(original);
                }
            }
            if (!_stopping) _failure ??= "LOCAL_FRAGMENT_RECV_UNCONFIRMED";
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }
    public async ValueTask DisposeAsync()
    {
        if (_unloaded) return; _stopping = true;
        if (!_library.Shutdown(_handle, 1)) _failure ??= "LOCAL_FRAGMENT_SHUTDOWN_UNCONFIRMED";
        await _worker.WaitAsync(TimeSpan.FromSeconds(5));
        if (!_library.Close(_handle)) throw new InvalidOperationException("LOCAL_FRAGMENT_CLOSE_UNCONFIRMED");
        _handle = IntPtr.Zero; _closed = 1; _library.Dispose(); _unloaded = true;
    }
}
