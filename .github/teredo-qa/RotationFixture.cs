using System.Text.Json.Nodes;
using VakoLink.AntiDpi.Windows;

internal static class RotationFixture
{
    internal static void Check()
    {
        var before = Snapshot("2001:0:aaaa::1", "fe80::123");
        var after = Snapshot("2001:0:bbbb::1", "fe80::456");
        var valid = Evaluate(before, after);
        Require(valid.Passed && valid.TeredoTransitions is [{ ReasonCode: "VERIFIED_TEREDO_ADDRESS_ROTATION" }], "ROTATION");
        Reject(before, after, "DEFAULT_REMOVED", s => s["Routes"]!.AsArray().RemoveAt(0));
        Reject(before, after, "DEFAULT_METRIC", s => s["Routes"]![0]!["RouteMetric"] = 255);
        Reject(before, after, "DEFAULT_GATEWAY", s => s["Routes"]![0]!["NextHop"] = "fe80::9");
        Reject(before, after, "IPV6_PREFIX_DRIFT", s => s["Routes"]![1]!["DestinationPrefix"] = "2001:0::/48");
        Reject(before, after, "UNRELATED_HOST_ROUTE", s => s["Routes"]![4]!["DestinationPrefix"] = "fe80::999/128");
        Reject(before, after, "DUPLICATE_HOST_ROUTE", s => s["Routes"]![4] = s["Routes"]![3]!.DeepClone());
        Reject(before, after, "NATIVE_GUID", s => s["NativeInterfaces"]![0]!["Guid"] = Guid.NewGuid().ToString());
        Reject(before, after, "NOT_TEREDO", s => s["NativeInterfaces"]![0]!["TunnelType"] = 0);
        Reject(before, after, "IP_INTERFACE", s => s["Interfaces"]![0]!["InterfaceMetric"] = 4);
        Reject(before, after, "REAL_DNS", s => s["DNS"]![0]!["ServerAddresses"] = new JsonArray("2001:db8::53"));
        Reject(before, after, "OTHER_DEFAULT", s => s["Routes"]!.AsArray().Add(JsonNode.Parse(
            """{"InterfaceIndex":7,"AddressFamily":2,"DestinationPrefix":"0.0.0.0/0","NextHop":"192.0.2.1","RouteMetric":1}""")));
        Reject(before, after, "SOCKS_LOOP", s => s["Routes"]!.AsArray().Add(JsonNode.Parse(
            """{"InterfaceIndex":96,"AddressFamily":2,"DestinationPrefix":"127.0.0.0/8","NextHop":"0.0.0.0","RouteMetric":1}""")));

        var during = (JsonObject)after.DeepClone();
        during["Adapters"]!.AsArray().Add(JsonNode.Parse(
            """{"InterfaceIndex":96,"Name":"VakoLink Aion Proxy","HardwareInterface":false,"Status":"Up"}"""));
        during["Addresses"]!.AsArray().Add(JsonNode.Parse(
            """{"InterfaceIndex":96,"AddressFamily":23,"IPAddress":"fe80::cafe","PrefixLength":64,"PrefixOrigin":2}"""));
        var proxy = new LocalProxyEndpoint("127.0.0.1", 10808, 0, DateTime.UnixEpoch, 0, []);
        foreach (bool ipv4Only in new[] { true, false })
        {
            var config = ProxyTunPlan.Build(proxy, null, "Ethernet", "Loopback", "172.29.16.1/30", 1234, "fixture",
                selectedApplications: [Environment.ProcessPath!], ipv4Only: ipv4Only);
            var captured = (JsonObject)during.DeepClone();
            if (!ipv4Only) captured["Addresses"]!.AsArray().RemoveAt(2);
            var cleanup = ProxyCleanupPolicy.Assess(before, captured, after, config);
            Require(cleanup.SafeToReleaseJournal && cleanup.OwnershipVerified && cleanup.StartIsolationVerified,
                ipv4Only ? "IPV4_CLEANUP" : "OLD_JOURNAL_CLEANUP");
        }
    }

    private static void Reject(JsonObject before, JsonObject after, string test, Action<JsonObject> edit)
    {
        var modified = (JsonObject)after.DeepClone();
        edit(modified);
        Require(!Evaluate(before, modified).Passed, test);
    }

    private static NetworkIsolationCheck Evaluate(JsonObject before, JsonObject after) =>
        ProxyNetworkIsolation.Evaluate(before, after, 96, "127.0.0.1", 3, 1000);

    private static void Require(bool passed, string code)
    {
        if (!passed) throw new IOException("FIXTURE_FAILED_" + code);
    }

    private static JsonObject Snapshot(string teredo, string local) => JsonNode.Parse($$"""
        {
          "Physical":{"Index":5,"Hardware":true},"Proxy":{"Enable":1},"Firewall":[],
          "Adapters":[{"InterfaceIndex":13,"HardwareInterface":false,"Name":"Synthetic","Status":"Up"}],
          "NativeInterfaces":[{"InterfaceIndex":13,"Guid":"6e432694-8c13-4d55-a60f-9d7184e8eba9","Type":131,"TunnelType":14,"Hardware":false,"AdminStatus":1,"OperStatus":1,"Mtu":1280}],
          "Interfaces":[{"InterfaceIndex":13,"AddressFamily":23,"InterfaceMetric":1,"NlMtu":1280,"Dhcp":1,"ConnectionState":1}],
          "DNS":[{"InterfaceIndex":13,"AddressFamily":23,"ServerAddresses":[]}],
          "Addresses":[
            {"InterfaceIndex":13,"AddressFamily":23,"IPAddress":"{{teredo}}","PrefixLength":64,"PrefixOrigin":4},
            {"InterfaceIndex":13,"AddressFamily":23,"IPAddress":"{{local}}","PrefixLength":64,"PrefixOrigin":2}
          ],
          "Routes":[
            {"InterfaceIndex":13,"AddressFamily":23,"DestinationPrefix":"::/0","NextHop":"::","RouteMetric":256},
            {"InterfaceIndex":13,"AddressFamily":23,"DestinationPrefix":"2001:0::/32","NextHop":"::","RouteMetric":256},
            {"InterfaceIndex":13,"AddressFamily":23,"DestinationPrefix":"fe80::/64","NextHop":"::","RouteMetric":256},
            {"InterfaceIndex":13,"AddressFamily":23,"DestinationPrefix":"{{teredo}}/128","NextHop":"::","RouteMetric":256},
            {"InterfaceIndex":13,"AddressFamily":23,"DestinationPrefix":"{{local}}/128","NextHop":"::","RouteMetric":256},
            {"InterfaceIndex":13,"AddressFamily":23,"DestinationPrefix":"ff00::/8","NextHop":"::","RouteMetric":256}
          ]
        }
        """)!.AsObject();
}
