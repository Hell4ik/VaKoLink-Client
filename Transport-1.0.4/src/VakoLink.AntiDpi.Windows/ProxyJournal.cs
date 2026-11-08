using System.Diagnostics;
using System.Text.Json.Nodes;

namespace VakoLink.AntiDpi.Windows;

public static class ProxyJournal
{
    public static string MarkerPath => Path.Combine(ProxyTunPlan.Root, "active-operation.json");
    public static async Task<JsonObject> RecoverAsync(string script, IReadOnlyList<LocalProxyMember>? proxyMembers = null)
    {
        using var lease = new SessionDependencies().AcquireLease();
        if (!File.Exists(MarkerPath)) return new JsonObject { ["Recovered"] = false, ["NoPendingJournal"] = true };
        TunPrivateStore.VerifyImagePath(MarkerPath);
        var original = await File.ReadAllBytesAsync(MarkerPath); if (original.Length > 8192) throw new IOException("TUN_RECOVERY_JOURNAL_INVALID");
        var marker = JsonNode.Parse(original)!.AsObject();
        string op = (string)marker["Operation"]!; if (!Guid.TryParseExact(op, "N", out _)) throw new IOException("TUN_RECOVERY_JOURNAL_INVALID");
        int pid = (int)marker["ParentPid"]!;
        try
        {
            using var owner = Process.GetProcessById(pid);
            if (owner.StartTime.ToUniversalTime() == DateTime.Parse((string)marker["ParentBirthUtc"]!, null, System.Globalization.DateTimeStyles.RoundtripKind).ToUniversalTime())
                throw new IOException("TUN_OWNER_STILL_ALIVE_STOP_IN_WINDOW");
        }
        catch (ArgumentException) { }
        foreach (var core in Process.GetProcessesByName("sing-box"))
        {
            using (core)
                if (!(proxyMembers ?? []).Any(m => m.Pid == core.Id && m.BirthUtc.ToUniversalTime() == core.StartTime.ToUniversalTime() && string.Equals(m.Path, core.MainModule?.FileName, StringComparison.OrdinalIgnoreCase)))
                    throw new IOException("TUN_RECOVERY_CORE_STILL_PRESENT");
        }
        string folder = Path.Combine(ProxyTunPlan.Root, op); TunPrivateStore.VerifyImagePath(folder);
        foreach (string name in new[] { "baseline.dpapi", "configuration.dpapi", "during.dpapi" }) TunPrivateStore.VerifyImagePath(Path.Combine(folder, name));
        var before = TunPrivateStore.ReadProtected(Path.Combine(folder, "baseline.dpapi"));
        var config = TunPrivateStore.ReadProtected(Path.Combine(folder, "configuration.dpapi"));
        string duringPath = Path.Combine(folder, "during.dpapi"); var during = File.Exists(duringPath) ? TunPrivateStore.ReadProtected(duringPath) : null;
        var current = await ProxyTunSession.SnapshotAsync(script); var assessment = ProxyCleanupPolicy.Assess(before, during, current, config);
        TunPrivateStore.WriteProtected(Path.Combine(folder, "recovery-after.dpapi"), current.ToJsonString());
        var result = new JsonObject { ["Recovered"] = assessment.SafeToReleaseJournal, ["Operation"] = op,
            ["OwnerAbsent"] = true, ["OwnedCoreAbsent"] = true, ["Assessment"] = System.Text.Json.JsonSerializer.SerializeToNode(assessment),
            ["BaselineAfter"] = System.Text.Json.JsonSerializer.SerializeToNode(ProxyTunSession.Compare(before, current)), ["NetworkMutationCommandsUsed"] = false,
            ["NetworkDifferences"] = System.Text.Json.JsonSerializer.SerializeToNode(ProxyNetworkIsolation.DescribeChanges(before, current)),
            ["GlobalStateRestoredClaimed"] = assessment.GlobalBaselineEqual, ["ExternalStatePreserved"] = true,
            ["RecoveryPolicy"] = "OwnedFootprintAndCapturedMutationScope_v2_NotFullWindowsRollback" };
        SaveResult(folder, op, result);
        if (!assessment.SafeToReleaseJournal) throw new IOException(assessment.Blockers.First());
        // Archive first. Never delete the evidence or restore someone else's DNS/routes/proxy settings.
        foreach (string name in new[] { "run-config.json", "core-stderr.txt" })
        {
            string file = Path.Combine(folder, name); TunPrivateStore.VerifyImagePath(file);
            if (File.Exists(file)) { TunPrivateStore.WriteProtected(Path.Combine(folder, "recovered-" + name + ".dpapi"), await File.ReadAllTextAsync(file)); File.Delete(file); }
        }
        if (!(await File.ReadAllBytesAsync(MarkerPath)).AsSpan().SequenceEqual(original)) throw new IOException("TUN_RECOVERY_JOURNAL_CHANGED");
        File.Move(MarkerPath, Path.Combine(folder, "closed-marker-" + Guid.NewGuid().ToString("N") + ".json"));
        result["MarkerReleased"] = true; SaveResult(folder, op, result); return result;
    }
    private static void SaveResult(string folder, string op, JsonObject result)
    {
        File.WriteAllText(Path.Combine(folder, "recovery-safe.json"), result.ToJsonString());
        try
        {
            string reports = Path.Combine(ProxyTunPlan.Root, "Reports"); TunPrivateStore.EnsurePrivate(reports);
            string file = Path.Combine(reports, "safe-recovery-" + op + ".json");
            File.WriteAllText(file + ".tmp", result.ToJsonString()); File.Move(file + ".tmp", file, true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A failed secondary diagnostic export must neither authorize nor prevent an otherwise proven release.
            result["PublicReportSaved"] = false;
            File.WriteAllText(Path.Combine(folder, "recovery-safe.json"), result.ToJsonString());
        }
    }
}
