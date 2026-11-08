using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;

namespace VakoLink.AntiDpi.Windows;

public sealed record TeredoTransition(int InterfaceIndex, string IdentitySha256, string ReasonCode,
    int RemovedIpInterfaceRows, int RemovedDnsRows, int RemovedAddressRows, int RemovedRouteRows,
    bool RestorationRequired = false);

/// <summary>Native-identity-proven automatic Teredo lifecycle, never arbitrary non-hardware drift. No Windows mutations.</summary>
public static class TeredoTransitionPolicy
{
    private static readonly string[] Keys = ["Adapters", "Interfaces", "DNS", "Addresses", "Routes"];
    private static JsonObject[] Rows(JsonObject s, string key, int index) => s[key] is JsonArray a
        ? a.OfType<JsonObject>().Where(n => (int?)n["InterfaceIndex"] == index).ToArray() : [];
    private static JsonObject? Identity(JsonObject s, int index)
    {
        var rows = Rows(s, "NativeInterfaces", index);
        if (rows.Length != 1) return null;
        var n = rows[0];
        return (int?)n["Type"] == 131 && (int?)n["TunnelType"] == 14 && (bool?)n["Hardware"] == false
            && Guid.TryParse((string?)n["Guid"], out var guid) && guid != Guid.Empty ? n : null;
    }
    private static bool SameIdentity(JsonObject b, JsonObject a) => (string?)b["Guid"] == (string?)a["Guid"];
    public static IReadOnlyList<TeredoTransition> Recognize(JsonObject before, JsonObject during, int own)
    {
        var result = new List<TeredoTransition>();
        foreach (var adapter in (before["Adapters"] as JsonArray ?? []).OfType<JsonObject>())
        {
            int index = (int?)adapter["InterfaceIndex"] ?? -1;
            if (index <= 0 || index == own || index == (int?)before["Physical"]?["Index"] || index == (int?)during["Physical"]?["Index"]
                || Identity(before, index) is not { } b || Identity(during, index) is not { } d || !SameIdentity(b, d)) continue;
            var oldAdapters = Rows(before, "Adapters", index); var newAdapters = Rows(during, "Adapters", index);
            if (oldAdapters.Length != 1 || newAdapters.Length != 1 || (bool?)adapter["HardwareInterface"] != false
                || (string?)adapter["Status"] is not ("Up" or "Disabled") || (string?)newAdapters[0]["Status"] is not ("Up" or "Disabled")
                || (int?)b["AdminStatus"] is not (1 or 2) || (int?)b["OperStatus"] is not (1 or 2 or 5 or 6) || (int?)b["Mtu"] is not > 0
                || !ProxyNetworkIsolation.Equivalent(b["Mtu"], d["Mtu"]) || (int?)d["AdminStatus"] is not (1 or 2) || (int?)d["OperStatus"] is not (1 or 2 or 5 or 6)) continue;
            var expectedAdapter = adapter.DeepClone().AsObject(); expectedAdapter["Status"] = newAdapters[0]["Status"]!.DeepClone();
            if (!ProxyNetworkIsolation.Equivalent(expectedAdapter, newAdapters[0])) continue;
            var bi = Rows(before, "Interfaces", index); var di = Rows(during, "Interfaces", index);
            if (bi.Length == 1 && di.Length == 1)
            {
                var expected = bi[0].DeepClone().AsObject(); expected["ConnectionState"] = di[0]["ConnectionState"]?.DeepClone();
                if (!ProxyNetworkIsolation.Equivalent(expected, di[0])) continue; // Never normalize MTU/DHCP/metric edits.
            }
            if (!AutomaticState(before, index) || !AutomaticState(during, index)
                || Keys.All(key => ProxyNetworkIsolation.Equivalent(new JsonArray(Rows(before, key, index).Select(n => n.DeepClone()).ToArray()),
                    new JsonArray(Rows(during, key, index).Select(n => n.DeepClone()).ToArray())))) continue;
            int Removed(string key) => Math.Max(0, Rows(before, key, index).Length - Rows(during, key, index).Length);
            result.Add(new(index, AionTunPlan.Hash((string)b["Guid"]!), "VERIFIED_TEREDO_AUTOMATIC_LIFECYCLE",
                Removed("Interfaces"), Removed("DNS"), Removed("Addresses"), Removed("Routes")));
        }
        return result;
    }
    private static bool AutomaticState(JsonObject before, int index)
    {
            var interfaces = Rows(before, "Interfaces", index);
            var dns = Rows(before, "DNS", index); var addresses = Rows(before, "Addresses", index); var routes = Rows(before, "Routes", index);
            return (interfaces.Length == 0 || interfaces.Length == 1 && interfaces[0].Count == 6 && (int?)interfaces[0]["InterfaceMetric"] is >= 0
                && (int?)interfaces[0]["AddressFamily"] == 23 && (int?)interfaces[0]["NlMtu"] == 1280
                && (int?)interfaces[0]["Dhcp"] == 1 && (int?)interfaces[0]["ConnectionState"] is 0 or 1)
                && dns.Length <= 2 && dns.Select(n => (int?)n["AddressFamily"]).Distinct().Count() == dns.Length
                && !dns.Any(n => n.Count != 3 || (int?)n["AddressFamily"] is not (2 or 23)
                    || n["ServerAddresses"] is not JsonArray { Count: 0 })
                && addresses.Length <= 2 && addresses.All(AutomaticAddress)
                && routes.Length <= 8 && routes.All(OnLinkRoute);
    }
    private static bool AutomaticAddress(JsonObject n) => n.Count == 5 && (int?)n["AddressFamily"] == 23
        && (int?)n["PrefixLength"] == 64 && IPAddress.TryParse((string?)n["IPAddress"], out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6
        && (ip.IsIPv6Teredo && (int?)n["PrefixOrigin"] == 4 || ip.IsIPv6LinkLocal && (int?)n["PrefixOrigin"] == 2);
    private static bool OnLinkRoute(JsonObject n)
    {
        if (n.Count != 5 || (int?)n["AddressFamily"] != 23 || (string?)n["NextHop"] != "::" || (int?)n["RouteMetric"] != 256) return false;
        var parts = ((string?)n["DestinationPrefix"] ?? "").Split('/');
        if (parts.Length != 2 || !int.TryParse(parts[1], out int length) || !IPAddress.TryParse(parts[0], out var ip)
            || ip.AddressFamily != AddressFamily.InterNetworkV6) return false;
        // No default/gateway/IPv4/ULA/unrelated global scope. The projection cannot prove route authorship.
        return ip.IsIPv6Teredo && length is >= 32 and <= 128 || ip.IsIPv6LinkLocal && length is >= 64 and <= 128
            || ip.Equals(IPAddress.Parse("ff00::")) && length == 8;
    }
    public static JsonArray Excluding(JsonNode? rows, int own, IReadOnlyList<TeredoTransition> transitions)
        => new(rows!.AsArray().Where(n => (int?)n?["InterfaceIndex"] != own
            && !transitions.Any(t => t.InterfaceIndex == (int?)n?["InterfaceIndex"])).Select(n => n!.DeepClone()).ToArray());

    public static bool Restored(JsonObject baseline, JsonObject current, TeredoTransition transition)
    {
        int index = transition.InterfaceIndex;
        return Identity(baseline, index) is { } b && Identity(current, index) is { } a && SameIdentity(b, a)
            && AionTunPlan.Hash((string)b["Guid"]!) == transition.IdentitySha256
            && ProxyNetworkIsolation.Equivalent(b, a)
            && Keys.All(key => ProxyNetworkIsolation.Equivalent(new JsonArray(Rows(baseline, key, index).Select(n => n.DeepClone()).ToArray()),
                new JsonArray(Rows(current, key, index).Select(n => n.DeepClone()).ToArray())));
    }
}
