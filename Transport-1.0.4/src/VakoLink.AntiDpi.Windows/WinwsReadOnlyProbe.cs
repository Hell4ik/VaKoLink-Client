using System.Text;
using System.Text.RegularExpressions;

namespace VakoLink.AntiDpi.Windows;

public sealed record WinwsProbeEvidence(string ExecutableSha256, string? VersionLine, int VersionExit,
    int DryRunExit, int InvalidOptionExit, bool ParametersAccepted, bool InvalidOptionRejected, bool OutputBoundReached,
    string Basis = "Pinned file; private ConPTY --version and --dry-run only. No live filter, payload logging or configuration mutation.");
public static class WinwsReadOnlyProbe
{
    public static async Task<WinwsProbeEvidence> RunAsync(string engine, IReadOnlyList<string> parameters)
    {
        RuntimePreflight.VerifyFile(Path.Combine(engine, "winws.exe"), OriginalZapretReference.PinnedWinwsSha256);
        RuntimePreflight.VerifyFile(Path.Combine(engine, "cygwin1.dll"), OriginalZapretReference.PinnedCygwinSha256);
        var version = await RunOne(engine, ["--version"]);
        var dry = await RunOne(engine, new[] { "--dry-run" }.Concat(parameters).ToArray());
        var invalid = await RunOne(engine, ["--dry-run", "--vakolink-invalid-option-must-fail"]);
        var match = Regex.Match(version.Text, @"github version v?72\.9 \(c849e55ef0f1c244206f5a05ff7b1ab41a3824ee\)");
        return new(OriginalZapretReference.PinnedWinwsSha256, match.Success ? match.Value : null, version.Code, dry.Code,
            invalid.Code, dry.Code == 0, invalid.Code != 0, version.Limited || dry.Limited || invalid.Limited);
    }
    private static async Task<(int Code, string Text, bool Limited)> RunOne(string engine, string[] parameters)
    {
        var output = new StringBuilder(); bool limited = false;
        var terminal = OwnedConsoleProcess.Start(Path.Combine(engine, "winws.exe"), parameters, engine, (bytes, size) =>
        {
            int remaining = 65536 - output.Length;
            if (remaining < size) limited = true;
            if (remaining > 0) output.Append(Encoding.UTF8.GetString(bytes, 0, Math.Min(remaining, size)));
        });
        try { await terminal.Process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(8)); }
        catch { if (!terminal.Process.HasExited) { terminal.Process.Kill(); await terminal.Process.WaitForExitAsync(); } throw; }
        finally { await terminal.DisposeAfterExitAsync(); }
        int code = terminal.Process.ExitCode; terminal.Process.Dispose();
        return (code, output.ToString(), limited);
    }
}
