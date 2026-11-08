using System.Diagnostics;

namespace VakoLink.AntiDpi.Windows;

public sealed record AionC3LaunchEvidence(bool Passed, string? Failure, WinwsProbeEvidence? Probe,
    bool InvalidPositionRejected, ResearchFilterEvidence? Filter, FragmentFilterEvidence? FragmentFilter,
    bool EngineStarted, bool AliveAfterStartup, bool StopSignalSent, bool ProcessExited, bool ForcedTermination,
    bool InputsReleased, bool LeaseReleased, IReadOnlyList<string> LaunchArguments,
    bool FalseFilterOnly = true, bool LocalhostFixtureUsed = false, bool PacketMonitorUsed = false,
    int GameAttempts = 0, int OwnPacketsSent = 0,
    string FragmentationObservation = "UnknownNotProven",
    string Scope = "C3 parser/synthetic filter and own original winws lifecycle with wf-raw=false; zero traffic can match. No game, localhost traffic, Packet Monitor, network settings or external process control. This is not fragmentation/efficacy proof.");

public static class AionC3LaunchVerification
{
    public static async Task<AionC3LaunchEvidence> RunAsync(string engine)
    {
        if (!RuntimePreflight.IsAdministrator()) throw new InvalidOperationException("ADMIN_REQUIRED");
        if (RuntimePreflight.GetConflicts().Count != 0) throw new InvalidOperationException("CONFLICTING_ENGINE_ACTIVE");
        var arguments = AionZapretResearchPlan.BuildArguments("false", AionOriginalCandidate.C3Ipfrag2);
        var locks = new List<IDisposable>(); IDisposable? lease = null; OwnedConsoleProcess? terminal = null; ProcessIdentity? identity = null;
        WinwsProbeEvidence? probe = null; ResearchFilterEvidence? filter = null; FragmentFilterEvidence? fragments = null;
        string? failure = null; bool badPosition = false, started = false, alive = false, signaled = false, exited = false, forced = false;
        try
        {
            lease = new SessionDependencies().AcquireLease();
            foreach (var name in new[] { "winws.exe", "cygwin1.dll", "WinDivert.dll", "WinDivert64.sys" })
            {
                var path = Path.Combine(engine, name);
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("C3_REPARSE_INPUT");
                locks.Add(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read));
            }
            RuntimePreflight.VerifyPackage(engine, CancellationToken.None);
            probe = await WinwsReadOnlyProbe.RunAsync(engine, arguments);
            var invalid = await WinwsReadOnlyProbe.RunAsync(engine, arguments.Select(a => a == "--dpi-desync-ipfrag-pos-tcp=32" ? "--dpi-desync-ipfrag-pos-tcp=31" : a).ToArray());
            badPosition = invalid.DryRunExit != 0;
            filter = ResearchFilterVerification.VerifyReservedSyntheticTarget(engine);
            fragments = ResearchFilterVerification.VerifyFragments(engine, "198.51.100.2", 13328, false);
            if (!probe.ParametersAccepted || !probe.InvalidOptionRejected || !badPosition || !filter.Passed || !fragments.Passed)
                throw new InvalidOperationException("C3_PARAMETER_OR_FILTER_INVALID");
            terminal = OwnedConsoleProcess.Start(Path.Combine(engine, "winws.exe"), arguments, engine); started = true;
            identity = ProcessOwnership.ReadIdentity((uint)terminal.Process.Id);
            if (identity is null || !string.Equals(identity.ImagePath, Path.GetFullPath(Path.Combine(engine, "winws.exe")), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("C3_LAUNCH_IDENTITY_UNCONFIRMED");
            await Task.Delay(500); alive = !terminal.Process.HasExited;
            if (!alive) throw new InvalidOperationException("C3_ENGINE_EXITED_EARLY");
        }
        catch (Exception ex) { failure = ex is InvalidOperationException ? ex.Message : "C3_LAUNCH_" + ex.GetType().Name; }
        finally
        {
            try
            {
                if (terminal is not null)
                {
                    var process = terminal.Process;
                    if (!process.HasExited)
                    {
                        // Private ConPTY only; never a console-wide signal or external service stop.
                        signaled = terminal.SendInterrupt();
                        try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); }
                        catch (TimeoutException)
                        {
                            var current = ProcessOwnership.ReadIdentity((uint)process.Id);
                            if (identity is null || current is null || !OwnershipPolicy.SameIdentity(identity, current))
                                throw new InvalidOperationException("C3_STOP_IDENTITY_UNCONFIRMED");
                            forced = true; process.Kill(); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
                        }
                    }
                    exited = process.HasExited;
                    await terminal.DisposeAfterExitAsync(); process.Dispose(); terminal = null;
                }
            }
            catch (Exception ex) { failure ??= "C3_STOP_" + ex.GetType().Name; }
            finally { foreach (var file in locks) file.Dispose(); locks.Clear(); lease?.Dispose(); lease = null; }
        }
        bool passed = failure is null && started && alive && signaled && exited && !forced && terminal is null;
        return new(passed, failure, probe, badPosition, filter, fragments, started, alive, signaled, exited, forced, locks.Count == 0, lease is null, arguments);
    }
}
