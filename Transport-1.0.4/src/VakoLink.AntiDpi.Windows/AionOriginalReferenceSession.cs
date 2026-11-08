using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public sealed record AionOriginalEvidence(string Candidate, string TargetAddressSha256, ushort Port,
    IReadOnlyList<string> RedactedArguments, string ActualArgumentsSha256, WinwsProbeEvidence? Probe,
    OriginalZapretEvidence Engine, NativeEvidence PassiveNative, GamePassiveEvidence Before, GamePassiveEvidence After,
    AionReferenceProofEvidence Proof, bool OwnActiveBackend = false, bool ProcessBoundEngine = false,
    string Scope = "Original winws exact IPv4 address+TCP port, NOT PID binding; other processes using this endpoint also match. Own observers SNIFF|RECV_ONLY only. No BAT/service/network configuration commands.",
    ResearchFilterEvidence? FilterVerification = null, AionFakeProofEvidence? FakeProof = null,
    IReadOnlyList<AionReferenceCoordinates>? BeforeCoordinates = null, IReadOnlyList<AionReferenceCoordinates>? AfterCoordinates = null,
    AionFragmentEvidence? FragmentProof = null, FragmentFixtureEvidence? LocalFragmentFixture = null,
    FragmentFilterEvidence? FragmentFilter = null)
{
    // Derived from measured proof, NEVER from engine startup or the user game outcome.
    public string FragmentationObservation => Candidate != AionZapretResearchPlan.C3Candidate ? "NotApplicable"
        : !Engine.Started ? "NotStarted"
        : FragmentProof is { MatchingFragmentPairs: > 0 } ? "ConfirmedCapturePairs" : "UnknownNotProven";
}

public sealed class AionOriginalReferenceSession : IAsyncDisposable
{
    private readonly SessionDependencies _deps = new(); private readonly AppProfile _main;
    private readonly IReadOnlyList<AppProfile> _profiles;
    private readonly SemaphoreSlim _stopGate = new(1, 1); private readonly List<IDisposable> _locks = [];
    private IDisposable? _lease; private OwnedConsoleProcess? _terminal; private ProcessIdentity? _identity;
    private readonly AionReferenceProof _proof = new(); private AionReferenceProofEvidence? _finalProof;
    private readonly AionOriginalCandidate _candidate; private AionFakeProofEvidence? _finalFakeProof;
    private readonly AionIpv4FragmentProof _fragments = new(); private AionFragmentEvidence? _finalFragments;
    private CancellationTokenRegistration _cancel;
    private bool _started, _signaled, _forced, _exited;
    private bool _loopback; private ushort _port = 13328;
    private string _argvHash = new('0', 64); private WinwsProbeEvidence? _probe;
    private ResearchFilterEvidence? _filterVerification;
    private FragmentFilterEvidence? _fragmentFilter;
    public GamePassiveTrace Before { get; }
    public GamePassiveTrace After { get; }
    public bool Running => _terminal is not null && !_terminal.Process.HasExited && Before.Evidence.Running && After.Evidence.Running;
    public AionOriginalReferenceSession(AppProfile main, IReadOnlyList<AppProfile> profiles, AionOriginalCandidate candidate = AionOriginalCandidate.C1Multidisorder)
    {
        _main = main; _profiles = profiles; _candidate = candidate; _ = AionZapretResearchPlan.CandidateId(candidate);
        var passive = new SessionDependencies { AcquireLease = () => new EmptyLease() };
        Before = new(profiles, passive, true); After = new(profiles, passive, true);
    }
    private sealed class EmptyLease : IDisposable { public void Dispose() { } }
    public AionOriginalEvidence Evidence
    {
        get
        {
            var b = Before.Evidence; var a = After.Evidence;
            var native = new NativeEvidence(b.Native.Opened + a.Native.Opened, b.Native.Closed + a.Native.Closed,
                b.Native.DllLoaded || a.Native.DllLoaded, (!b.Native.DllLoaded || b.Native.DllUnloaded) && (!a.Native.DllLoaded || a.Native.DllUnloaded),
                b.Native.RollbackCompleted && a.Native.RollbackCompleted && (!_started || _exited) && _lease is null);
            var engine = new OriginalZapretEvidence(AionZapretResearchPlan.CandidateId(_candidate), OriginalZapretReference.PinnedWinwsSha256,
                _argvHash, _argvHash, _started, _terminal is not null && !_terminal.Process.HasExited, _signaled, _exited, _forced,
                (!_started || _exited) && _terminal is null && _lease is null && _locks.Count == 0,
                _loopback ? "Own localhost lifecycle fixture: winws explicitly passes loopback; NOT desync proof; ephemeral local port only"
                    : AionZapretResearchPlan.EngineScope);
            var redacted = AionZapretResearchPlan.BuildArguments("[PINNED_IPV4_BIDIRECTIONAL_TCP13328_NOT_PID_BOUND]", _candidate).ToArray();
            if (_loopback) { redacted[0] = "--wf-raw=[OWN_LOOPBACK_EPHEMERAL_PORT]"; redacted[2] = "--filter-tcp=[OWN_EPHEMERAL_PORT]"; }
            return new(AionZapretResearchPlan.CandidateId(_candidate), _loopback ? Convert.ToHexString(SHA256.HashData(new byte[] { 127, 0, 0, 1 })) : AionTcpSegmentation.TargetAddressSha256, _port,
                redacted, _argvHash,
                _probe, engine, native, b, a, _finalProof ?? _proof.Snapshot(Stopwatch.Frequency), FilterVerification: _filterVerification,
                FakeProof: _candidate == AionOriginalCandidate.C2FakeBadseq ? _finalFakeProof ?? _proof.FakeSnapshot(Stopwatch.Frequency) : null,
                BeforeCoordinates: AionReferenceCoordinates.From(b), AfterCoordinates: AionReferenceCoordinates.From(a),
                FragmentProof: _candidate == AionOriginalCandidate.C3Ipfrag2 ? _finalFragments ?? _fragments.Snapshot(Stopwatch.Frequency) : null,
                FragmentFilter: _fragmentFilter);
        }
    }
    public async Task StartAsync(string engine, string address, CancellationToken token)
    {
        if (_started || _lease is not null) throw new InvalidOperationException("AION_REFERENCE_ONE_ATTEMPT_ONLY");
        if (!RuntimePreflight.IsAdministrator()) throw new InvalidOperationException("ADMIN_REQUIRED");
        // Explicit C3 research policy: unproven capture is reported Unknown, not a game-launch gate.
        // Parameter/filter/image/ownership/report/cleanup checks remain mandatory.
        if (!_profiles.All(p => p.StrategyId == "observe") || (_loopback ? _main.ExecutablePath != Environment.ProcessPath
            : ProfileBindingCollector.HashImage(_main).Sha256 != AionTcpSegmentation.ClientImageSha256 || !GameComponentTrust.IsSignedNcImage(_main.ExecutablePath))) throw new InvalidOperationException("AION_REFERENCE_IMAGE_UNCONFIRMED");
        if (RuntimePreflight.GetConflicts().Count != 0) throw new InvalidOperationException("CONFLICTING_ENGINE_ACTIVE");
        var arguments = _loopback ? AionZapretResearchPlan.BuildArguments(AionZapretResearchPlan.RawFilter("127.0.0.1", _port, true), _candidate)
            .Select(a => a == "--filter-tcp=13328" ? "--filter-tcp=" + _port : a).ToArray() : AionZapretResearchPlan.Arguments(address, _candidate);
        _argvHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', arguments))));
        try
        {
            _lease = _deps.AcquireLease();
            foreach (var p in new[] { _main.ExecutablePath, Path.Combine(engine, "winws.exe"), Path.Combine(engine, "cygwin1.dll"), Path.Combine(engine, "WinDivert.dll"), Path.Combine(engine, "WinDivert64.sys") })
            { if ((File.GetAttributes(p) & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("REFERENCE_REPARSE_INPUT"); _locks.Add(new FileStream(p, FileMode.Open, FileAccess.Read, FileShare.Read)); }
            RuntimePreflight.VerifyPackage(engine, token);
            if (!_loopback && (ProfileBindingCollector.HashImage(_main).Sha256 != AionTcpSegmentation.ClientImageSha256 || !GameComponentTrust.IsSignedNcImage(_main.ExecutablePath)))
                throw new InvalidOperationException("AION_REFERENCE_LOCKED_IMAGE_CHANGED");
            _probe = await WinwsReadOnlyProbe.RunAsync(engine, arguments);
            if (!_probe.ParametersAccepted || !_probe.InvalidOptionRejected || _probe.VersionLine is null) throw new InvalidOperationException("WINWS_REFERENCE_PREFLIGHT_FAILED");
            _filterVerification = _loopback ? ResearchFilterVerification.VerifyReservedSyntheticTarget(engine) : ResearchFilterVerification.Verify(engine, address);
            if (!_filterVerification.Passed) throw new InvalidOperationException("WINWS_REFERENCE_FILTER_SCOPE_FAILED");
            token.ThrowIfCancellationRequested();
            var filter = AionZapretResearchPlan.RawFilter(_loopback ? "127.0.0.1" : address, _port, _loopback).Replace(" and !impostor", "");
            Before.ConfigureReferenceObservation(30000, filter, (p, b, o, outgoing, q) =>
            {
                if (o.Identity.ImagePath == _main.ExecutablePath) { _proof.Observe(p, b, o, true, outgoing, q); if (_candidate == AionOriginalCandidate.C3Ipfrag2) _fragments.ObserveOriginal(p, b, o, outgoing, q); }
                return false;
            });
            var afterFilter = _candidate == AionOriginalCandidate.C3Ipfrag2
                ? AionZapretResearchPlan.FragmentObservationFilter(_loopback ? "127.0.0.1" : address, _port, _loopback) : filter;
            if (_candidate == AionOriginalCandidate.C3Ipfrag2)
            {
                _fragmentFilter = ResearchFilterVerification.VerifyFragments(engine, _loopback ? "127.0.0.1" : address, _port, _loopback);
                if (!_fragmentFilter.Passed) throw new InvalidOperationException("C3_FRAGMENT_FILTER_UNPROVEN");
            }
            After.ConfigureReferenceObservation(-30000, afterFilter, (p, b, o, outgoing, q) =>
            {
                if (o.Identity.ImagePath != _main.ExecutablePath) return false;
                bool fake = _candidate == AionOriginalCandidate.C2FakeBadseq && outgoing && _proof.IsKnownFake(p, b, o, q, Stopwatch.Frequency);
                _proof.Observe(p, b, o, false, outgoing, q); return fake;
            }, _candidate == AionOriginalCandidate.C3Ipfrag2 ? (b, outgoing, iface, q) => _fragments.ObserveFragment(b, outgoing, iface, q, Stopwatch.Frequency) : null,
                _candidate == AionOriginalCandidate.C3Ipfrag2 ? _fragments.RecordCapture : null);
            if (_loopback) { await Before.StartDetailedLoopbackSmokeAsync(engine, _port, CancellationToken.None); await After.StartDetailedLoopbackSmokeAsync(engine, _port, CancellationToken.None); }
            else { await Before.StartAsync(engine, CancellationToken.None); await After.StartAsync(engine, CancellationToken.None); }
            _terminal = OwnedConsoleProcess.Start(Path.Combine(engine, "winws.exe"), arguments, engine); _started = true;
            _identity = ProcessOwnership.ReadIdentity((uint)_terminal.Process.Id);
            if (_identity is null || !string.Equals(_identity.ImagePath, Path.GetFullPath(Path.Combine(engine, "winws.exe")), StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("REFERENCE_IDENTITY_UNCONFIRMED");
            _cancel = token.Register(() => _ = Task.Run(StopAsync));
            await Task.Delay(500, token); if (!Running) throw new InvalidOperationException("REFERENCE_EXITED_EARLY");
        }
        catch { await StopAsync(); throw; }
    }
    public async Task StopAsync()
    {
        await _stopGate.WaitAsync();
        try
        {
            _cancel.Unregister();
            if (_terminal is not null)
            {
                var p = _terminal.Process;
                if (!p.HasExited)
                {
                    var now = ProcessOwnership.ReadIdentity((uint)p.Id);
                    if (_identity is null || now is null || !OwnershipPolicy.SameIdentity(_identity, now)) throw new InvalidOperationException("REFERENCE_STOP_IDENTITY_UNCONFIRMED");
                    _signaled = _terminal.SendInterrupt();
                    try { await p.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); }
                    catch (TimeoutException) { _forced = true; p.Kill(); await p.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); }
                }
                _exited = p.HasExited; await _terminal.DisposeAfterExitAsync(); p.Dispose(); _terminal = null;
            }
            Exception? error = null;
            try { await Before.StopAsync(); } catch (Exception e) { error = e; }
            try { await After.StopAsync(); } catch (Exception e) { error ??= e; }
            _finalProof ??= _proof.Snapshot(Stopwatch.Frequency); _finalFakeProof ??= _proof.FakeSnapshot(Stopwatch.Frequency); _proof.Dispose();
            _finalFragments ??= _fragments.Snapshot(Stopwatch.Frequency); _fragments.Dispose();
            if (error is not null) throw new InvalidOperationException("REFERENCE_OBSERVER_ROLLBACK_UNCONFIRMED", error);
            foreach (var file in _locks) file.Dispose(); _locks.Clear(); _lease?.Dispose(); _lease = null;
        }
        finally { _stopGate.Release(); }
    }
    public async ValueTask DisposeAsync() => await StopAsync();
    public static async Task<(bool Passed, string? Failure, AionOriginalEvidence Evidence)> VerifyOwnLoopbackAsync(string engine, AionOriginalCandidate candidate = AionOriginalCandidate.C1Multidisorder)
    {
        using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0); listener.Start();
        ushort port = (ushort)((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        var main = new AppProfile("local-game", "Own original engine fixture", Environment.ProcessPath!, "observe");
        var session = new AionOriginalReferenceSession(main, [main], candidate) { _loopback = true, _port = port };
        string? failure = null; bool delivery = false; Task? server = null; AionFragmentLoopbackDivert? fixture = null; FragmentLoopbackAudit? audit = null;
        try
        {
            await session.StartAsync(engine, "127.0.0.1", budget.Token);
            if (candidate == AionOriginalCandidate.C3Ipfrag2) { audit = new(engine, port); fixture = new(engine, port, session.Before); }
            server = Task.Run(async () =>
            {
                using var peer = await listener.AcceptTcpClientAsync(budget.Token);
                for (int i = 0; i < 4; i++) { var bytes = new byte[11]; await peer.GetStream().ReadExactlyAsync(bytes, budget.Token); await peer.GetStream().WriteAsync(bytes, budget.Token); }
            });
            using var client = new System.Net.Sockets.TcpClient(); client.NoDelay = true;
            await client.ConnectAsync(System.Net.IPAddress.Loopback, port, budget.Token); await Task.Delay(300, budget.Token);
            for (int i = 0; i < 4; i++)
            {
                var data = Enumerable.Range(0, 11).Select(n => (byte)(i * 17 + n)).ToArray(); var result = new byte[11];
                await client.GetStream().WriteAsync(data, budget.Token); await client.GetStream().ReadExactlyAsync(result, budget.Token);
                if (!result.SequenceEqual(data)) throw new InvalidOperationException("LOCAL_STREAM_CHANGED"); await Task.Delay(60, budget.Token);
            }
            await server; await Task.Delay(250, budget.Token); delivery = true;
        }
        catch (Exception e) { failure = e.GetType().Name; }
        finally
        {
            budget.Cancel(); listener.Stop();
            if (server is not null) try { await server.WaitAsync(TimeSpan.FromSeconds(2)); } catch { }
            if (fixture is not null) try { await fixture.DisposeAsync(); } catch (Exception ex) { failure ??= "FIXTURE_STOP_" + ex.GetType().Name; }
            if (audit is not null) try { await audit.DisposeAsync(); } catch (Exception ex) { failure ??= "AUDIT_STOP_" + ex.GetType().Name; }
            try { await session.StopAsync(); } catch (Exception e) { failure ??= "STOP_" + e.GetType().Name; }
            if (server is { IsCompleted: false }) failure ??= "LOCAL_SERVER_TASK_RETAINED";
        }
        var evidence = session.Evidence with { LocalFragmentFixture = fixture is null ? null : fixture.Evidence with { Audit = audit?.Evidence } };
        // This version explicitly passes wa.Loopback in win_main: this is lifecycle/pass-through verification, NOT desync proof.
        if (candidate == AionOriginalCandidate.C3Ipfrag2)
        {
            var f = fixture?.Evidence;
            if (f is not { Opened: 1, Closed: 1, DllUnloaded: true, OriginalsFragmented: 4, FragmentsSent: 8, Failure: null }) failure ??= f?.Failure ?? "FRAGMENT_FIXTURE_INCOMPLETE";
            bool fragmentPassed = delivery && failure is null && evidence.FragmentProof is { MatchingFragmentPairs: 4, FragmentCopiesStored: 8, ReassembledCopies: 4, LimitDrops: 0 }
                && audit?.Evidence is { Closed: 1, DllUnloaded: true, Failure: null, MetadataDropped: 0 }
                && evidence.Proof.OriginalSizedAfterCopies == 4 && evidence.PassiveNative.Opened == 6 && evidence.PassiveNative.Closed == 6
                && evidence.PassiveNative.RollbackCompleted && evidence.Engine.CleanupConfirmed;
            return (fragmentPassed, failure ?? (fragmentPassed ? null : "FRAGMENT_OBSERVABILITY_UNPROVEN"), evidence);
        }
        bool passed = delivery && failure is null && evidence.Proof.MatchingSplits == 0 && evidence.Proof.ReverseSplits == 0
            && evidence.Proof.OriginalSizedAfterCopies == 4 && evidence.FilterVerification?.Passed == true
            && evidence.PassiveNative.Opened == 6 && evidence.PassiveNative.Closed == 6 && evidence.PassiveNative.RollbackCompleted && evidence.Engine.CleanupConfirmed;
        return (passed, failure, evidence);
    }
}
