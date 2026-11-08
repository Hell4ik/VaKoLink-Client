using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace VakoLink.AntiDpi.Windows;

public sealed record NetworkFieldDifference(string Row, string Field, string Expected, string Observed);
public sealed record NetworkIsolationPredicate(string Id, bool Passed, string ReasonCode,
    IReadOnlyList<NetworkFieldDifference> Differences, bool DifferencesTruncated = false);
public sealed record NetworkIsolationCheck(int Snapshot, long ElapsedMs, bool Passed, string? FailureCode,
    IReadOnlyList<NetworkIsolationPredicate> Predicates, IReadOnlyList<NetworkInterfaceContext>? InterfaceContexts = null,
    IReadOnlyList<TeredoTransition>? TeredoTransitions = null);
public sealed record NetworkInterfaceContext(int InterfaceIndex, string Snapshot, bool AdapterPresent, bool? Hardware,
    string? AdapterIdentitySha256, string? Status, int IpInterfaceRows, int DnsRows, int AddressRows, int RouteRows, bool SelectedPhysical,
    bool NativeIdentityAvailable = false, int? NativeType = null, int? NativeTunnelType = null, string? NativeIdentitySha256 = null);
public sealed record NetworkCategoryDifference(string Category, bool Equal, IReadOnlyList<NetworkFieldDifference> Differences, bool Truncated);
public sealed record NetworkCleanupCheck(DateTimeOffset Utc, IReadOnlyDictionary<string, bool> BaselineAfter,
    ProxyCleanupAssessment Assessment, IReadOnlyList<NetworkCategoryDifference>? Differences = null);

/// <summary>Read-only checks. Row ordering is irrelevant; duplicates, every field and DNS server order remain significant.</summary>
public static class ProxyNetworkIsolation
{
    public const int MaximumStartupSnapshots = 3;
    public const int RecheckDelayMilliseconds = 500;
    private const int MaximumDifferences = 64;

    public static bool Equivalent(JsonNode? expected, JsonNode? observed)
    {
        if (expected is JsonArray a && observed is JsonArray b)
            return a.Select(Canonical).Order(StringComparer.Ordinal).SequenceEqual(b.Select(Canonical).Order(StringComparer.Ordinal));
        return Canonical(expected) == Canonical(observed);
    }

    public static JsonArray WithoutInterface(JsonNode? rows, int own) => new(rows!.AsArray()
        .Where(n => (int?)n?["InterfaceIndex"] != own).Select(n => n!.DeepClone()).ToArray());

    public static bool EquivalentDnsServers(JsonNode? before, JsonNode? after)
    {
        static bool EmptyPlaceholder(JsonNode? n) => n is JsonObject o && o.Count == 3
            && o["InterfaceIndex"] is JsonValue index && index.TryGetValue<int>(out int i) && i > 0
            && o["AddressFamily"] is JsonValue family && family.TryGetValue<int>(out int f) && f is 2 or 23
            && o["ServerAddresses"] is JsonArray a && a.Count == 0;
        if (before is not JsonArray b || after is not JsonArray a) return Equivalent(before, after);
        return Equivalent(new JsonArray(b.Where(n => !EmptyPlaceholder(n)).Select(n => n!.DeepClone()).ToArray()),
            new JsonArray(a.Where(n => !EmptyPlaceholder(n)).Select(n => n!.DeepClone()).ToArray()));
    }

    public static NetworkIsolationCheck Evaluate(JsonObject baseline, JsonObject active, int own, string proxyHost, int snapshot, long elapsedMs)
    {
        var predicates = new List<NetworkIsolationPredicate>();
        var teredo = TeredoTransitionPolicy.Recognize(baseline, active, own);
        bool newIndex = new[] { "Adapters", "Routes", "Addresses", "Interfaces", "DNS" }
            .All(k => !baseline[k]!.AsArray().Any(n => (int?)n?["InterfaceIndex"] == own));
        predicates.Add(new("OWN_INTERFACE_INDEX_NEW", newIndex, newIndex ? "PASSED" : "INTERFACE_INDEX_ALREADY_PRESENT", []));
        bool loopbackExcluded = !active["Routes"]!.AsArray().Any(n => (int?)n?["InterfaceIndex"] == own
            && ProxyTunSession.PrefixMatches(proxyHost, (string?)n?["DestinationPrefix"]));
        predicates.Add(new("LOCAL_PROXY_ROUTE_EXCLUDED", loopbackExcluded, loopbackExcluded ? "PASSED" : "PROXY_ADDRESS_COVERED_BY_TUN_ROUTE", []));
        predicates.AddRange(EvaluateNonOwned(baseline, active, own, teredo));
        string? failure = predicates.FirstOrDefault(p => !p.Passed)?.Id switch
        {
            null => null,
            "OWN_INTERFACE_INDEX_NEW" => "TUN_OWN_INDEX_NOT_NEW_AT_START",
            "LOCAL_PROXY_ROUTE_EXCLUDED" => "TUN_LOCAL_PROXY_ROUTE_NOT_EXCLUDED",
            "NON_TUN_DNS_UNCHANGED" => "TUN_NON_TUN_DNS_CHANGED",
            "NON_TUN_IP_INTERFACES_UNCHANGED" => "TUN_NON_TUN_INTERFACE_CHANGED",
            "NON_TUN_ADAPTERS_UNCHANGED" => "TUN_NON_TUN_ADAPTER_CHANGED",
            "NON_TUN_ADDRESSES_UNCHANGED" => "TUN_NON_TUN_ADDRESS_CHANGED",
            "NON_TUN_ROUTES_UNCHANGED" => "TUN_NON_TUN_ROUTE_CHANGED",
            "SYSTEM_PROXY_UNCHANGED" => "TUN_SYSTEM_PROXY_CHANGED",
            "FIREWALL_PROFILES_UNCHANGED" => "TUN_FIREWALL_PROFILES_CHANGED",
            _ => "TUN_ROUTING_DNS_ISOLATION_FAILED"
        };
        var indexes = predicates.SelectMany(p => p.Differences).Select(d => d.Row).Where(r => r.StartsWith("interface=", StringComparison.Ordinal))
            .Select(r => int.Parse(r[10..].Split(';')[0], System.Globalization.CultureInfo.InvariantCulture)).Distinct().Take(16);
        var contexts = indexes.SelectMany(index => new[] { Context(baseline, index, "Before"), Context(active, index, "During") }).ToArray();
        return new(snapshot, elapsedMs, failure is null, failure, predicates, contexts, teredo);
    }

    // One authoritative startup audit, also used by cleanup/recovery. Cleanup ownership is a separate question.
    public static IReadOnlyList<NetworkIsolationPredicate> EvaluateNonOwned(JsonObject baseline, JsonObject active, int own,
        IReadOnlyList<TeredoTransition>? transitions = null)
    {
        var teredo = transitions ?? TeredoTransitionPolicy.Recognize(baseline, active, own);
        var predicates = new List<NetworkIsolationPredicate>();
        foreach (var (category, id) in new[] { ("DNS", "NON_TUN_DNS_UNCHANGED"), ("Interfaces", "NON_TUN_IP_INTERFACES_UNCHANGED"),
                     ("Proxy", "SYSTEM_PROXY_UNCHANGED"), ("Firewall", "FIREWALL_PROFILES_UNCHANGED"),
                     ("Adapters", "NON_TUN_ADAPTERS_UNCHANGED"), ("Addresses", "NON_TUN_ADDRESSES_UNCHANGED"), ("Routes", "NON_TUN_ROUTES_UNCHANGED") })
        {
            JsonNode? before = baseline[category], after = active[category];
            bool perInterface = category is "DNS" or "Interfaces" or "Adapters" or "Addresses" or "Routes";
            if (perInterface)
            { before = WithoutInterface(before, own); after = WithoutInterface(after, own); }
            bool rawEqual = Equivalent(before, after);
            bool passed = category == "DNS" ? EquivalentDnsServers(before, after) : perInterface
                ? Equivalent(TeredoTransitionPolicy.Excluding(before, own, teredo), TeredoTransitionPolicy.Excluding(after, own, teredo)) : rawEqual;
            var changes = rawEqual ? [] : Differences(before, after);
            predicates.Add(new(id, passed, rawEqual ? "PASSED" : !passed ? "SNAPSHOT_CONTENT_CHANGED" : category == "DNS"
                ? "EMPTY_DNS_PLACEHOLDER_ROWS_CHANGED" : "VERIFIED_TEREDO_AUTOMATIC_LIFECYCLE",
                changes.Take(MaximumDifferences).ToArray(), changes.Count > MaximumDifferences));
        }
        return predicates;
    }

    public static string? FinalFailure(string? previous, bool cleanupConfirmed)
        => cleanupConfirmed && (previous is "TUN_BASELINE_AFTER_MISMATCH" or "TUN_OWN_ADAPTER_REMAINS" or "TUN_OWN_ADDRESS_REMAINS"
            or "TUN_OWN_RANGE_ROUTE_REMAINS" or "TUN_OWN_NEXT_HOP_REMAINS" or "TUN_OWN_GUID_REMAINS" or "TUN_OWN_ROUTE_SIGNATURE_REMAINS"
            || previous?.StartsWith("TUN_OWN_INDEX_REMAINS_", StringComparison.Ordinal) == true) ? null : previous;

    public static bool CanRecheck(NetworkIsolationCheck check) => !check.Passed && check.Snapshot < MaximumStartupSnapshots
        && check.Predicates.Where(p => !p.Passed).All(p => p.Id is "NON_TUN_DNS_UNCHANGED" or "NON_TUN_IP_INTERFACES_UNCHANGED"
            or "NON_TUN_ADAPTERS_UNCHANGED" or "NON_TUN_ADDRESSES_UNCHANGED" or "NON_TUN_ROUTES_UNCHANGED");

    public static IReadOnlyList<NetworkCategoryDifference> DescribeChanges(JsonObject before, JsonObject after)
        => new[] { "Adapters", "Routes", "Addresses", "Interfaces", "DNS", "Firewall", "Proxy" }.Select(key =>
        {
            bool equal = Equivalent(before[key], after[key]);
            var changes = equal ? [] : Differences(before[key], after[key]);
            return new NetworkCategoryDifference(key, equal, changes.Take(MaximumDifferences).ToArray(), changes.Count > MaximumDifferences);
        }).Where(c => !c.Equal).ToArray();

    public static NetworkInterfaceContext Context(JsonObject snapshot, int index, string label)
    {
        var adapters = snapshot["Adapters"]!.AsArray().Where(n => (int?)n?["InterfaceIndex"] == index).ToArray();
        var adapter = adapters.Length == 1 ? adapters[0] : null;
        var identities = (snapshot["NativeInterfaces"] as JsonArray)?.Where(n => (int?)n?["InterfaceIndex"] == index).ToArray() ?? [];
        var native = identities.Length == 1 ? identities[0] : null;
        bool nativeAvailable = Guid.TryParse((string?)native?["Guid"], out var guid) && guid != Guid.Empty;
        int Count(string key) => snapshot[key]!.AsArray().Count(n => (int?)n?["InterfaceIndex"] == index);
        return new(index, label, adapters.Length > 0, (bool?)adapter?["HardwareInterface"], adapter is null ? null : Hash(
            (string?)adapter["Name"] + "|" + (string?)adapter["InterfaceDescription"]),
            adapter is null ? null : SafeValue("Status", adapter["Status"]), Count("Interfaces"), Count("DNS"), Count("Addresses"), Count("Routes"),
            (int?)snapshot["Physical"]?["Index"] == index, nativeAvailable, (int?)native?["Type"], (int?)native?["TunnelType"],
            nativeAvailable ? Hash(guid.ToString("D")) : null);
    }

    private static List<NetworkFieldDifference> Differences(JsonNode? before, JsonNode? after)
    {
        var result = new List<NetworkFieldDifference>();
        if (before is JsonObject bo && after is JsonObject ao) { CompareObject("settings", bo, ao, result); return result; }
        if (before is not JsonArray ba || after is not JsonArray aa)
        { result.Add(new("snapshot", "Value", SafeValue("Value", before), SafeValue("Value", after))); return result; }
        var oldRows = ba.GroupBy(RowKey).ToDictionary(g => g.Key, g => g.ToArray());
        var newRows = aa.GroupBy(RowKey).ToDictionary(g => g.Key, g => g.ToArray());
        foreach (string key in oldRows.Keys.Union(newRows.Keys).Order(StringComparer.Ordinal))
        {
            var old = oldRows.GetValueOrDefault(key) ?? []; var current = newRows.GetValueOrDefault(key) ?? [];
            if (old.Length == 1 && current.Length == 1 && old[0] is JsonObject ob && current[0] is JsonObject nb)
                CompareObject(key, ob, nb, result);
            else if (!Equivalent(new JsonArray(old.Select(n => n?.DeepClone()).ToArray()), new JsonArray(current.Select(n => n?.DeepClone()).ToArray())))
            {
                result.Add(new(key, "Rows", $"count={old.Length};sha256={Hash(string.Join('|', old.Select(Canonical).Order(StringComparer.Ordinal)))}",
                    $"count={current.Length};sha256={Hash(string.Join('|', current.Select(Canonical).Order(StringComparer.Ordinal)))}"));
                // Retain bounded changed-row fields (hashed addresses), not merely aggregate count/hash for multi-route interfaces.
                var unmatched = current.Select(Canonical).ToList(); var removed = new List<JsonNode?>();
                foreach (var row in old) { int match = unmatched.IndexOf(Canonical(row)); if (match >= 0) unmatched.RemoveAt(match); else removed.Add(row); }
                foreach (var row in removed.Take(4).OfType<JsonObject>()) CompareObject(key + ";removed", row, new(), result);
                var oldCounts = old.Select(Canonical).ToList(); var added = new List<JsonNode?>();
                foreach (var row in current) { int match = oldCounts.IndexOf(Canonical(row)); if (match >= 0) oldCounts.RemoveAt(match); else added.Add(row); }
                foreach (var row in added.Take(4).OfType<JsonObject>()) CompareObject(key + ";added", new(), row, result);
            }
        }
        return result;
    }
    private static void CompareObject(string row, JsonObject before, JsonObject after, List<NetworkFieldDifference> changes)
    {
        foreach (string field in before.Select(p => p.Key).Union(after.Select(p => p.Key)).Order(StringComparer.Ordinal))
            if (before.ContainsKey(field) != after.ContainsKey(field) || Canonical(before[field]) != Canonical(after[field]))
                changes.Add(new(row, SafeField(field), before.ContainsKey(field) ? SafeValue(field, before[field]) : "absent",
                    after.ContainsKey(field) ? SafeValue(field, after[field]) : "absent"));
    }
    private static string RowKey(JsonNode? node)
    {
        if (node is JsonObject o && o.ContainsKey("InterfaceIndex"))
            return "interface=" + SafeValue("InterfaceIndex", o["InterfaceIndex"]) + ";family=" + SafeValue("AddressFamily", o["AddressFamily"]);
        if (node is JsonObject p && p.ContainsKey("Name")) return "profile=" + SafeValue("Name", p["Name"]);
        return "row-sha256=" + Hash(Canonical(node));
    }
    private static string SafeField(string field) => field is "InterfaceIndex" or "AddressFamily" or "InterfaceMetric" or "NlMtu" or "Dhcp"
        or "ConnectionState" or "ServerAddresses" or "Enable" or "Server" or "Override" or "PAC" or "Name" or "Enabled"
        or "DefaultInboundAction" or "DefaultOutboundAction" or "IPAddress" or "DestinationPrefix" or "NextHop" or "RouteMetric"
        or "PrefixOrigin" or "PrefixLength" or "Status" or "HardwareInterface" or "InterfaceDescription" ? field : "field-sha256=" + Hash(field);
    private static string SafeValue(string field, JsonNode? value)
    {
        if (value is null) return "null";
        bool scalarField = field is "InterfaceIndex" or "AddressFamily" or "InterfaceMetric" or "NlMtu" or "Dhcp" or "ConnectionState"
            or "Enable" or "Enabled" or "DefaultInboundAction" or "DefaultOutboundAction" or "PrefixOrigin" or "PrefixLength" or "RouteMetric" or "HardwareInterface";
        if (scalarField && value is JsonValue j && (j.TryGetValue<bool>(out _) || j.TryGetValue<int>(out _))) return value.ToJsonString();
        if (value is JsonValue v && v.TryGetValue<string>(out var s) &&
            ((scalarField && s is "IPv4" or "IPv6" or "InterNetwork" or "InterNetworkV6" or "2" or "23" or "Connected" or "Disconnected" or "Enabled" or "Disabled" or "Allow" or "Block" or "NotConfigured")
             || field == "Name" && s is "Domain" or "Private" or "Public" || field == "Status" && s is "Up" or "Down" or "Disabled" or "Not Present" or "Unknown")) return s;
        return (value is JsonArray a ? $"count={a.Count};" : "") + "sha256=" + Hash(Canonical(value));
    }
    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private static string Canonical(JsonNode? node) => node switch
    {
        null => "null",
        JsonObject o => "{" + string.Join(',', o.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => System.Text.Json.JsonSerializer.Serialize(p.Key) + ":" + Canonical(p.Value))) + "}",
        JsonArray a => "[" + string.Join(',', a.Select(Canonical)) + "]",
        _ => node.ToJsonString()
    };
}
