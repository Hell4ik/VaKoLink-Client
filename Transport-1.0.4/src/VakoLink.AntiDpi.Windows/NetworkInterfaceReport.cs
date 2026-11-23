using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;

namespace VakoLink.AntiDpi.Windows;

// These records contain only exportable network metadata. Keep the raw snapshot and identities private.
public sealed record NetworkInterfaceReport(int InterfaceIndex, bool? SameIdentityAsBefore,
    NetworkInterfaceState Before, NetworkInterfaceState Current, IReadOnlyList<Ipv6AddressChange> AddressChanges,
    IReadOnlyList<Ipv6RouteChange> RouteChanges, bool ChangesTruncated);

public sealed record NetworkInterfaceState(bool AdapterPresent, bool? Hardware, int? NativeType, int? NativeTunnelType,
    bool PrimaryInterface, int Ipv6InterfaceRows, int Ipv6AddressRows, int Ipv6RouteRows);
public sealed record Ipv6AddressChange(string Change, string Scope, int? PrefixOrigin, int? SuffixOrigin,
    int? AddressState, int? PrefixLength, int Count);
public sealed record Ipv6RouteChange(string Change, string Scope, bool? ViaGateway, int? PrefixLength, int? Metric, int Count);

internal static class NetworkInterfaceReports
{
    private const int MaximumChangeGroups = 32;
    internal static int[] AffectedIndexes(IEnumerable<NetworkFieldDifference> changes) =>
        changes.Select(change => change.Row.Split(';', 2)[0])
            .Where(row => row.StartsWith("interface=", StringComparison.Ordinal))
            .Select(row => int.Parse(row.AsSpan("interface=".Length), System.Globalization.CultureInfo.InvariantCulture))
            .Distinct().Take(16).ToArray();

    internal static NetworkInterfaceReport[] Build(JsonObject baseline, JsonObject current, IEnumerable<int> interfaces) =>
        interfaces.Distinct().Take(16).Select(index => Compare(baseline, current, index)).ToArray();

    private static NetworkInterfaceReport Compare(JsonObject baseline, JsonObject current, int index)
    {
        var before = ProxyNetworkIsolation.Context(baseline, index, "Before");
        var after = ProxyNetworkIsolation.Context(current, index, "Current");
        bool? sameIdentity = before.NativeIdentityAvailable && after.NativeIdentityAvailable
            ? before.NativeIdentitySha256 == after.NativeIdentitySha256 : null;

        var baselineAddresses = Ipv6Rows(baseline, index, "Addresses");
        var currentAddresses = Ipv6Rows(current, index, "Addresses");
        var addresses = ChangedRows(baselineAddresses, currentAddresses)
            .GroupBy(item =>
            {
                var snapshot = item.Change == "Removed" ? baseline : current;
                var detail = AddressDetail(snapshot, item.Row);
                return (item.Change, Scope: Scope((string?)item.Row["IPAddress"]), Origin: (int?)item.Row["PrefixOrigin"],
                    SuffixOrigin: (int?)detail?["SuffixOrigin"], AddressState: (int?)detail?["AddressState"],
                    PrefixLength: (int?)item.Row["PrefixLength"]);
            })
            .Select(group => new Ipv6AddressChange(group.Key.Change, group.Key.Scope, group.Key.Origin,
                group.Key.SuffixOrigin, group.Key.AddressState, group.Key.PrefixLength, group.Count())).ToArray();

        var baselineRoutes = Ipv6Rows(baseline, index, "Routes");
        var currentRoutes = Ipv6Rows(current, index, "Routes");
        var routes = ChangedRows(baselineRoutes, currentRoutes)
            .GroupBy(item =>
            {
                var parts = ((string?)item.Row["DestinationPrefix"] ?? "").Split('/', 2);
                int? length = parts.Length == 2 && int.TryParse(parts[1], out int prefixLength) ? prefixLength : null;
                bool? gateway = IPAddress.TryParse((string?)item.Row["NextHop"], out var nextHop)
                    ? !nextHop.Equals(IPAddress.IPv6Any) : null;
                return (item.Change, Scope: length == 0 ? "Default" : Scope(parts[0]), ViaGateway: gateway,
                    PrefixLength: length, Metric: (int?)item.Row["RouteMetric"]);
            })
            .Select(group => new Ipv6RouteChange(group.Key.Change, group.Key.Scope, group.Key.ViaGateway,
                group.Key.PrefixLength, group.Key.Metric, group.Count())).ToArray();
        return new(index, sameIdentity, State(baseline, before, baselineAddresses, baselineRoutes),
            State(current, after, currentAddresses, currentRoutes),
            addresses.Take(MaximumChangeGroups).ToArray(), routes.Take(MaximumChangeGroups).ToArray(),
            addresses.Length > MaximumChangeGroups || routes.Length > MaximumChangeGroups);
    }

    private static NetworkInterfaceState State(JsonObject snapshot, NetworkInterfaceContext context,
        JsonObject[] addresses, JsonObject[] routes) =>
        new(context.AdapterPresent, context.Hardware, context.NativeType, context.NativeTunnelType, context.SelectedPhysical,
            Ipv6Rows(snapshot, context.InterfaceIndex, "Interfaces").Length, addresses.Length, routes.Length);

    private static JsonObject[] Ipv6Rows(JsonObject snapshot, int index, string category) =>
        (snapshot[category] as JsonArray ?? []).OfType<JsonObject>()
            .Where(row => (int?)row["InterfaceIndex"] == index && (int?)row["AddressFamily"] == 23).ToArray();

    private static JsonObject? AddressDetail(JsonObject snapshot, JsonObject address) =>
        (snapshot["IPv6AddressDetails"] as JsonArray ?? []).OfType<JsonObject>().FirstOrDefault(row =>
            (int?)row["InterfaceIndex"] == (int?)address["InterfaceIndex"] &&
            (int?)row["PrefixLength"] == (int?)address["PrefixLength"] &&
            (string?)row["IPAddress"] == (string?)address["IPAddress"]);

    private static IEnumerable<(string Change, JsonObject Row)> ChangedRows(JsonObject[] before, JsonObject[] after)
    {
        var remaining = after.ToList();
        foreach (var row in before)
        {
            int match = remaining.FindIndex(candidate => ProxyNetworkIsolation.Equivalent(row, candidate));
            if (match >= 0) remaining.RemoveAt(match);
            else yield return ("Removed", row);
        }
        foreach (var row in remaining) yield return ("Added", row);
    }

    private static string Scope(string? value)
    {
        if (!IPAddress.TryParse(value, out var address) || address.AddressFamily != AddressFamily.InterNetworkV6)
            return "Unknown";
        if (address.IsIPv6LinkLocal) return "LinkLocal";
        if (address.IsIPv6Teredo) return "Teredo";
        if (address.IsIPv6Multicast) return "Multicast";
        if (IPAddress.IsLoopback(address)) return "Loopback";
        if (address.Equals(IPAddress.IPv6Any)) return "Unspecified";
        var bytes = address.GetAddressBytes();
        if ((bytes[0] & 0xfe) == 0xfc) return "UniqueLocal";
        return (bytes[0] & 0xe0) == 0x20 ? "GlobalUnicast" : "Other";
    }
}
