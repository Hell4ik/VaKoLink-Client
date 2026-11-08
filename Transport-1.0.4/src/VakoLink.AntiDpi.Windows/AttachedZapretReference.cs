using System.Diagnostics;
using System.Runtime.InteropServices;

namespace VakoLink.AntiDpi.Windows;

// Read-only attachment: never sends Ctrl+C, kills, reconfigures or owns the user's winws.
public sealed class AttachedZapretReference
{
    private readonly ProcessIdentity _identity;
    public ReferenceConfiguration Configuration { get; }
    private AttachedZapretReference(ProcessIdentity identity, ReferenceConfiguration configuration)
    { _identity = identity; Configuration = configuration; }
    public bool Running
    {
        get
        {
            var now = ProcessOwnership.ReadIdentity(_identity.ProcessId);
            return now is not null && OwnershipPolicy.SameIdentity(_identity, now);
        }
    }
    public OriginalZapretEvidence Evidence => new("general (ALT13)", OriginalZapretReference.PinnedWinwsSha256,
        Configuration.Evidence.BatSha256, Configuration.Evidence.NormalizedArgvSha256,
        false, Running, false, false, false, true,
        "Attached existing ALT13 preserved; cleanup refers only to own passive observer, NOT stopping foreign engine.", "NOT_OWNED_PRESERVED");
    public static AttachedZapretReference Inspect(string engine)
    {
        if (Mutex.TryOpenExisting("Local\\VakoLink.AntiDpi.Interception", out var lease))
        { lease.Dispose(); throw new InvalidOperationException("OTHER_ACTIVE_INTERCEPTION"); }
        RuntimePreflight.VerifyPackage(engine, default);
        var expectedPath = Path.GetFullPath(Path.Combine(engine, "winws.exe"));
        RuntimePreflight.VerifyFile(expectedPath, OriginalZapretReference.PinnedWinwsSha256);
        var conflicts = RuntimePreflight.GetConflicts();
        if (conflicts.Count != 1) throw new InvalidOperationException("EXACTLY_ONE_ORIGINAL_ENGINE_REQUIRED");
        var processes = Process.GetProcessesByName("winws");
        try
        {
            if (processes.Length != 1) throw new InvalidOperationException("EXACTLY_ONE_ORIGINAL_ENGINE_REQUIRED");
            uint id = checked((uint)processes[0].Id); var identity = ProcessOwnership.ReadIdentity(id);
            if (identity is null || !identity.ImagePath.Equals(expectedPath, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("REFERENCE_IDENTITY_UNCONFIRMED");
            var command = CommandLine(id);
            var resolved = ReferenceConfiguration.Read(engine);
            var root = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(Path.GetFullPath(engine)))!;
            var arguments = OriginalZapretReference.ParseArguments(command, root, null);
            var actual = new ReferenceConfiguration(root, arguments, resolved.Evidence.BatSha256, "ATTACHED_ACTUAL_LAUNCH_ARGV");
            if (!actual.Evidence.Arguments.SequenceEqual(resolved.Evidence.Arguments)) throw new InvalidOperationException("RUNNING_ALT13_DIFFERS_FROM_RESOLVED_CONFIGURATION");
            var now = ProcessOwnership.ReadIdentity(id);
            if (now is null || !OwnershipPolicy.SameIdentity(identity, now)) throw new InvalidOperationException("REFERENCE_IDENTITY_CHANGED");
            return new(identity, actual);
        }
        finally { foreach (var process in processes) process.Dispose(); }
    }
    private static string CommandLine(uint id)
    {
        object? locator = null, service = null, rows = null, item = null;
        try
        {
            locator = Activator.CreateInstance(Type.GetTypeFromProgID("WbemScripting.SWbemLocator") ?? throw new InvalidOperationException("WMI_UNAVAILABLE"));
            service = ((dynamic)locator!).ConnectServer(".", "root\\cimv2");
            rows = ((dynamic)service).ExecQuery("SELECT CommandLine FROM Win32_Process WHERE ProcessId=" + id.ToString(System.Globalization.CultureInfo.InvariantCulture));
            string? text = null;
            foreach (var row in (System.Collections.IEnumerable)rows)
            {
                item = row; text = (string?)((dynamic)row).CommandLine; Marshal.FinalReleaseComObject(row); item = null;
            }
            if (text is null || text.Length > 16384 || !text.Contains("--wf-tcp=", StringComparison.Ordinal)) throw new InvalidOperationException("REFERENCE_COMMANDLINE_UNAVAILABLE");
            return text;
        }
        finally
        {
            foreach (var value in new[] { item, rows, service, locator }) if (value is not null && Marshal.IsComObject(value)) Marshal.FinalReleaseComObject(value);
        }
    }
}
