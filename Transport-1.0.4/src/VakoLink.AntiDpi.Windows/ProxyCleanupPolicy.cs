using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;

namespace VakoLink.AntiDpi.Windows;

public sealed record ProxyCleanupAssessment(bool OwnFootprintAbsent, bool StartIsolationVerified, bool GlobalBaselineEqual,
    bool SafeToReleaseJournal, int? OwnInterfaceIndex, IReadOnlyList<string> Blockers, IReadOnlyList<string> GlobalChangedCategories,
    string Basis = "Owned adapter/index/address/route/DNS footprint; global comparison retained separately",
    IReadOnlyList<TeredoTransition>? TeredoTransitions = null, bool? TeredoRestorationConfirmed = null,
    bool OwnershipVerified = false, bool MutationScopeVerified = false,
    string ExternalStateDisposition = "NotChecked", IReadOnlyList<NetworkIsolationPredicate>? StartupAudit = null);

public static class ProxyCleanupPolicy
{
    private static readonly string[] InterfaceKeys = ["Adapters", "Routes", "Addresses", "Interfaces", "DNS"];
    public static ProxyCleanupAssessment Assess(JsonObject baseline, JsonObject? during, JsonObject current, JsonObject config)
    {
        var blockers = new List<string>(); var compare = ProxyTunSession.Compare(baseline, current);
        var changed = compare.Where(kv => !kv.Value).Select(kv => kv.Key).ToArray();
        bool globalEqual = compare.Values.All(x => x); int? ownIndex = null; bool isolated = false;
        IReadOnlyList<TeredoTransition> teredo = [];
        bool ownership = false; IReadOnlyList<NetworkIsolationPredicate> audit = [];
        var tun = (config["inbounds"] as JsonArray)?.OfType<JsonObject>().Where(n => (string?)n["type"] == "tun").ToArray() ?? [];
        if (tun.Length != 1 || (string?)tun[0]?["interface_name"] != ProxyTunPlan.AdapterName ||
            (string?)tun[0]?["dns_mode"] != "disabled" || (bool?)tun[0]?["strict_route"] != false)
            blockers.Add("TUN_RECOVERY_PLAN_UNVERIFIED");
        string[] prefixes = tun.Length == 1 ? tun[0]?["address"]?.AsArray().Select(n => (string)n!).ToArray() ?? [] : [];
        bool prefixesValid = prefixes.Length == 2 && prefixes.All(ValidPrivatePrefix);
        prefixesValid = prefixesValid && prefixes.Select(p => p.Contains(':')).Distinct().Count() == 2;
        if (!prefixesValid) blockers.Add("TUN_RECOVERY_ADDRESS_PLAN_UNVERIFIED");
        if (Rows(baseline, "Adapters").Any(n => (string?)n["Name"] == ProxyTunPlan.AdapterName)) blockers.Add("TUN_BASELINE_OWN_ADAPTER_ALREADY_PRESENT");
        if (Rows(current, "Adapters").Any(n => (string?)n["Name"] == ProxyTunPlan.AdapterName)) blockers.Add("TUN_OWN_ADAPTER_REMAINS");
        if (prefixesValid)
        {
            if (Rows(current, "Addresses").Any(n => prefixes.Any(p => ProxyTunSession.PrefixMatches((string)n["IPAddress"]!, p)))) blockers.Add("TUN_OWN_ADDRESS_REMAINS");
            if (Rows(current, "Routes").Any(n => prefixes.Any(p => IsOwnedRangeRoute((string)n["DestinationPrefix"]!, p)))) blockers.Add("TUN_OWN_RANGE_ROUTE_REMAINS");
            if (Rows(current, "Routes").Any(n => n["NextHop"] is JsonValue hop && hop.TryGetValue<string>(out var address)
                    && prefixes.Any(p => ProxyTunSession.PrefixMatches(address, p)))) blockers.Add("TUN_OWN_NEXT_HOP_REMAINS");
        }
        if (during is not null)
        {
            var own = Rows(during, "Adapters").Where(n => (string?)n["Name"] == ProxyTunPlan.AdapterName).ToArray();
            if (own.Length == 1 && (bool?)own[0]["HardwareInterface"] == false)
            {
                ownIndex = (int)own[0]["InterfaceIndex"]!;
                ownership = !InterfaceKeys.Any(key => Rows(baseline, key).Any(n => (int?)n["InterfaceIndex"] == ownIndex));
                if (!ownership) blockers.Add("TUN_OWN_INDEX_NOT_NEW_AT_START");
                if (prefixesValid && Rows(during, "Addresses").Any(n => (int?)n["InterfaceIndex"] == ownIndex
                    && !prefixes.Any(p => ProxyTunSession.PrefixMatches((string)n["IPAddress"]!, p))))
                { ownership = false; blockers.Add("TUN_CAPTURED_ADDRESS_PLAN_MISMATCH"); }
                foreach (string key in InterfaceKeys)
                    if (Rows(current, key).Any(n => (int?)n["InterfaceIndex"] == ownIndex)) blockers.Add("TUN_OWN_INDEX_REMAINS_" + key.ToUpperInvariant());
                // Account for every mutation-capable network category, not just disappearance of the adapter name.
                teredo = TeredoTransitionPolicy.Recognize(baseline, during, ownIndex.Value);
                audit = ProxyNetworkIsolation.EvaluateNonOwned(baseline, during, ownIndex.Value, teredo);
                isolated = audit.All(p => p.Passed);
                var identity = (during["NativeInterfaces"] as JsonArray)?.OfType<JsonObject>().Where(n => (int?)n["InterfaceIndex"] == ownIndex).ToArray() ?? [];
                if (identity.Length > 1 || identity.Length == 1 && (!Guid.TryParse((string?)identity[0]["Guid"], out var captured) || captured == Guid.Empty))
                { ownership = false; blockers.Add("TUN_CAPTURED_IDENTITY_AMBIGUOUS"); }
                if (identity.Length == 1 && Guid.TryParse((string?)identity[0]["Guid"], out var guid) && guid != Guid.Empty
                    && current["NativeInterfaces"] is JsonArray native && native.Any(n => Guid.TryParse((string?)n?["Guid"], out var found) && found == guid))
                    blockers.Add("TUN_OWN_GUID_REMAINS");
                var oldRoutes = Rows(baseline, "Routes").Select(RouteSignature).ToHashSet(StringComparer.Ordinal);
                var ownRoutes = Rows(during, "Routes").Where(n => (int?)n["InterfaceIndex"] == ownIndex).Select(RouteSignature)
                    .Where(s => !oldRoutes.Contains(s)).ToHashSet(StringComparer.Ordinal);
                if (Rows(current, "Routes").Any(n => ownRoutes.Contains(RouteSignature(n)))) blockers.Add("TUN_OWN_ROUTE_SIGNATURE_REMAINS");
            }
        }
        // Owned resources and the whole Windows network are different lifetimes. Never restore unrelated Windows state.
        bool scope = MutationScopeVerified(config);
        if (!globalEqual && !ownership) blockers.Add("TUN_OWNERSHIP_NOT_PROVEN");
        if (!globalEqual && !scope) blockers.Add("TUN_RECOVERY_MUTATION_SCOPE_UNVERIFIED");
        bool? teredoRestored = teredo.Count == 0 ? null : teredo.All(t => TeredoTransitionPolicy.Restored(baseline, current, t));
        bool absent = prefixesValid && (ownership || globalEqual) && !blockers.Any(b => b.Contains("REMAINS", StringComparison.Ordinal));
        return new(absent, isolated, globalEqual, blockers.Count == 0, ownIndex, blockers, changed,
            Basis: "Verified owned footprint; exited core/secret removal/marker ownership checked separately; external state audit is NOT a restoration claim",
            TeredoTransitions: teredo, TeredoRestorationConfirmed: teredoRestored, OwnershipVerified: ownership,
            MutationScopeVerified: scope, ExternalStateDisposition: globalEqual ? "ExactBaseline" : "ObservedNotRestored_NoExternalRepair", StartupAudit: audit);
    }
    private static string RouteSignature(JsonObject row) => new JsonArray("AddressFamily", "DestinationPrefix", "NextHop")
        .Select(n => row[(string)n!]?.ToJsonString() ?? "null").Aggregate("", (a, b) => a + "|" + b);
    private static bool MutationScopeVerified(JsonObject config)
    {
        if (config["inbounds"] is not JsonArray inputs || inputs.Count is < 1 or > 3 || inputs.Any(n => n is not JsonObject)) return false;
        var tun = inputs.OfType<JsonObject>().Where(n => (string?)n["type"] == "tun").ToArray();
        if (tun.Length != 1) return false;
        string[] keys = ["type", "tag", "interface_name", "address", "mtu", "stack", "auto_route", "strict_route", "dns_mode", "route_exclude_address"];
        var t = tun[0];
        if (t.Any(p => !keys.Contains(p.Key)) || (string?)t["tag"] != "game-tun" || (int?)t["mtu"] != 1500
            || (string?)t["stack"] != "mixed" || (bool?)t["auto_route"] != true) return false;
        var expected = new JsonArray("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8");
        return ProxyNetworkIsolation.Equivalent(t["route_exclude_address"], expected)
            && inputs.OfType<JsonObject>().Where(n => (string?)n["type"] != "tun").All(n => (string?)n["type"] == "socks" && (string?)n["listen"] == "127.0.0.1");
    }
    private static IEnumerable<JsonObject> Rows(JsonObject snapshot, string key) => snapshot[key]!.AsArray().Select(n => n!.AsObject());
    private static bool ValidPrivatePrefix(string prefix)
    {
        var p = prefix.Split('/'); if (p.Length != 2 || !IPAddress.TryParse(p[0], out var ip)) return false;
        byte[] b = ip.GetAddressBytes(); return ip.AddressFamily == AddressFamily.InterNetwork ? p[1] == "30" && b[0] == 172 && b[1] == 29
            : p[1] == "126" && b[0] == 0xfd && b[1] == 0x94 && b[2] == 0x61 && b[3] == 0xe9;
    }
    private static bool IsOwnedRangeRoute(string route, string prefix)
    {
        var r = route.Split('/'); var p = prefix.Split('/');
        return r.Length == 2 && int.TryParse(r[1], out int length) && length >= int.Parse(p[1]) && ProxyTunSession.PrefixMatches(r[0], prefix);
    }
}
