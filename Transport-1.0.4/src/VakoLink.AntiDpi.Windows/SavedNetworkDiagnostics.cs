using System.Net.NetworkInformation;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace VakoLink.AntiDpi.Windows;

// Export existing private snapshots, never start/stop a core, release a journal, or modify the network.
public static class SavedNetworkDiagnostics
{
    public static string OperationFromTimeline(string value)
    {
        if (!value.StartsWith("media-", StringComparison.Ordinal) || !Guid.TryParseExact(value[6..], "N", out _))
            throw new IOException("DIAGNOSTICS_OPERATION_INVALID");
        return value[6..];
    }
    public static JsonObject Summarize(JsonObject before, JsonObject during, JsonObject? after)
    {
        var changes = ProxyNetworkIsolation.DescribeChanges(before, during);
        var own = during["Adapters"]!.AsArray().Where(n => (string?)n?["Name"] == ProxyTunPlan.AdapterName).ToArray();
        int ownIndex = own.Length == 1 ? (int)own[0]!["InterfaceIndex"]! : -1;
        var ids = changes.SelectMany(c => c.Differences).Select(d => d.Row).Where(r => r.StartsWith("interface=", StringComparison.Ordinal))
            .Select(r => int.Parse(r[10..].Split(';')[0], System.Globalization.CultureInfo.InvariantCulture)).Where(i => i != ownIndex).Distinct().Take(16).ToArray();
        var contexts = ids.SelectMany(i => after is null
            ? new[] { ProxyNetworkIsolation.Context(before, i, "Before"), ProxyNetworkIsolation.Context(during, i, "During") }
            : new[] { ProxyNetworkIsolation.Context(before, i, "Before"), ProxyNetworkIsolation.Context(during, i, "During"), ProxyNetworkIsolation.Context(after, i, "After") });
        return new JsonObject
        {
            ["OwnInterfaceIndexAtCapture"] = ownIndex,
            ["BeforeDuringDifferences"] = JsonSerializer.SerializeToNode(changes),
            ["BeforeAfterDifferences"] = after is null ? null : JsonSerializer.SerializeToNode(ProxyNetworkIsolation.DescribeChanges(before, after)),
            ["InterfaceContexts"] = JsonSerializer.SerializeToNode(contexts.ToArray()),
            ["RelevantInterfaceIndexes"] = JsonSerializer.SerializeToNode(ids),
            ["VerifiedTeredoTransitionsAtCapture"] = JsonSerializer.SerializeToNode(TeredoTransitionPolicy.Recognize(before, during, ownIndex)),
            ["StartupNonOwnedAudit"] = ownIndex < 0 ? null : JsonSerializer.SerializeToNode(ProxyNetworkIsolation.EvaluateNonOwned(before, during, ownIndex)),
            ["DnsServerConfigurationUnchanged"] = ownIndex < 0 ? null : ProxyNetworkIsolation.EquivalentDnsServers(before["DNS"], ProxyNetworkIsolation.WithoutInterface(during["DNS"], ownIndex))
        };
    }
    public static string ExportLast()
    {
        string reports = Path.Combine(ProxyTunPlan.Root, "Reports");
        if (!Directory.Exists(reports)) throw new IOException("DIAGNOSTICS_SAVED_REPORT_NOT_FOUND");
        TunPrivateStore.VerifyImagePath(reports);
        foreach (var report in new DirectoryInfo(reports).EnumerateFiles("safe-report-*.json").OrderByDescending(f => f.LastWriteTimeUtc).Take(64))
        {
            TunPrivateStore.VerifyImagePath(report.FullName);
            if (report.Length > 2_000_000) continue;
            var source = JsonNode.Parse(File.ReadAllText(report.FullName))!.AsObject();
            if ((string?)source["Discord"]?["TimelineDirectory"] is not { } timeline) continue;
            string op = OperationFromTimeline(timeline), folder = Path.Combine(ProxyTunPlan.Root, op);
            if (!File.Exists(Path.Combine(folder, "baseline.dpapi")) || !File.Exists(Path.Combine(folder, "during.dpapi"))) continue;
            TunPrivateStore.VerifyImagePath(folder);
            foreach (string name in new[] { "baseline.dpapi", "during.dpapi", "after.dpapi" })
            {
                string file = Path.Combine(folder, name); TunPrivateStore.VerifyImagePath(file);
                if (File.Exists(file) && new FileInfo(file).Length > 2_000_000) throw new IOException("DIAGNOSTICS_SNAPSHOT_TOO_LARGE");
            }
            var before = TunPrivateStore.ReadProtected(Path.Combine(folder, "baseline.dpapi"));
            var during = TunPrivateStore.ReadProtected(Path.Combine(folder, "during.dpapi"));
            var after = File.Exists(Path.Combine(folder, "after.dpapi")) ? TunPrivateStore.ReadProtected(Path.Combine(folder, "after.dpapi")) : null;
            var result = Summarize(before, during, after);
            result["Kind"] = "SavedNetworkContext_ReadOnlyExport"; result["CreatedUtc"] = DateTimeOffset.UtcNow;
            result["OriginalReportSha256"] = AionTunPlan.FileHash(report.FullName);
            result["OriginalReportUpdatedUtc"] = DateTimeOffset.TryParse((string?)source["UpdatedUtc"], out var time) ? JsonValue.Create(time) : null;
            result["OriginalFailure"] = (string?)source["Session"]?["Failure"] is { } error ? ProxyTunSession.SafeCode(new IOException(error)) : null;
            result["CurrentMetadataIsNotHistoricalOwnershipProof"] = true;
            result["NetworkMutationCommandsUsed"] = false; result["CoreStarted"] = false; result["MarkerDeletedOrArchived"] = false;
            result["CurrentInterfaceMetadata"] = CurrentMetadata(result["RelevantInterfaceIndexes"]!.AsArray().Select(n => (int)n!).ToArray());
            string output = Path.Combine(reports, "safe-network-context-" + Guid.NewGuid().ToString("N") + ".json");
            File.WriteAllText(output, result.ToJsonString(new JsonSerializerOptions { WriteIndented = true })); return output;
        }
        throw new IOException("DIAGNOSTICS_SAVED_SNAPSHOTS_NOT_FOUND");
    }
    private static JsonArray CurrentMetadata(int[] relevant)
    {
        var rows = new JsonArray();
        foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            try
            {
                var properties = adapter.GetIPProperties(); int? v4 = adapter.Supports(NetworkInterfaceComponent.IPv4) ? properties.GetIPv4Properties()?.Index : null;
                int? v6 = adapter.Supports(NetworkInterfaceComponent.IPv6) ? properties.GetIPv6Properties()?.Index : null;
                if (!relevant.Contains(v4 ?? -1) && !relevant.Contains(v6 ?? -1)) continue;
                string kind = adapter.NetworkInterfaceType == NetworkInterfaceType.Tunnel && adapter.Description.Contains("Teredo", StringComparison.OrdinalIgnoreCase) ? "WindowsTeredo"
                    : adapter.NetworkInterfaceType == NetworkInterfaceType.Tunnel && adapter.Description.Contains("ISATAP", StringComparison.OrdinalIgnoreCase) ? "WindowsIsatap"
                    : adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback ? "Loopback" : "Unclassified";
                rows.Add(new JsonObject { ["Ipv4Index"] = v4, ["Ipv6Index"] = v6, ["InterfaceType"] = adapter.NetworkInterfaceType.ToString(),
                    ["KnownComponent"] = kind, ["Status"] = adapter.OperationalStatus.ToString(),
                    ["IdentitySha256"] = AionTunPlan.Hash(adapter.Name + "|" + adapter.Description), ["ObservationUtc"] = DateTimeOffset.UtcNow });
            }
            catch (NetworkInformationException) { }
        }
        return rows;
    }
}
