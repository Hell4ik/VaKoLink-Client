using System.Net;
using System.Text.Json.Nodes;

namespace VakoLink.AntiDpi.Windows;

public static class ProxyTunPlan
{
    public const string AdapterName = "VakoLink Aion Proxy";
    public static string Root => AppContext.GetData("VaKoLink.Client.TransportData") as string ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VakoLink", "AionTransportProxy");
    public static string ChooseAddress(JsonObject baseline)
    {
        // Avoid ANY existing address or non-default route overlapping the /30, not merely the host IP.
        for (int i = 16; i < 240; i++)
        {
            string network = $"172.29.{i}.0/30", address = $"172.29.{i}.1";
            bool collision = baseline["Addresses"]!.AsArray().Any(a => AionTunSession.PrefixMatches((string)a!["IPAddress"]!, network)) ||
                baseline["Routes"]!.AsArray().Any(r => (string?)r?["DestinationPrefix"] is { } prefix && prefix != "0.0.0.0/0" && prefix.Contains('.') &&
                    (AionTunSession.PrefixMatches(address, prefix) || AionTunSession.PrefixMatches(prefix.Split('/')[0], network)));
            if (!collision) return address + "/30";
        }
        throw new IOException("TUN_NO_FREE_PRIVATE_RANGE");
    }
    public static string ChooseIpv6Address(JsonObject baseline)
    {
        for (int i = 16; i < 240; i++)
        {
            string address = $"fd94:61e9:{i:x}::1", network = $"fd94:61e9:{i:x}::/126";
            if (!baseline["Addresses"]!.AsArray().Any(a => AionTunSession.PrefixMatches((string)a!["IPAddress"]!, network)) &&
                !baseline["Routes"]!.AsArray().Any(r => (string?)r?["DestinationPrefix"] is { } p && p.Contains(':') && p != "::/0" &&
                    (AionTunSession.PrefixMatches(address, p) || AionTunSession.PrefixMatches(p.Split('/')[0], network)))) return address + "/126";
        }
        throw new IOException("TUN_NO_FREE_IPV6_RANGE");
    }
    public static JsonObject Build(LocalProxyEndpoint proxy, string main, string physical, string loopback, string address, int api, string secret, int probe = 0, string ipv6 = "fd94:61e9:10::1/126", IReadOnlyList<DiscordComponentPin>? discord = null, int discordProbe = 0)
    {
        if (!IPAddress.IsLoopback(IPAddress.Parse(proxy.Host)) || proxy.Port is < 1 or > 65535 || proxy.Members.Any(m => string.Equals(m.Path, main, StringComparison.OrdinalIgnoreCase))) throw new IOException("PROXY_LOOP_GUARD_INVALID");
        var excludes = proxy.Members.Select(m => m.Path).Append(AionTunPlan.CorePath).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var rules = new JsonArray(new JsonObject { ["process_path"] = new JsonArray(excludes.Select(p => (JsonNode?)JsonValue.Create(p)).ToArray()), ["action"] = "route", ["outbound"] = "direct" },
            new JsonObject { ["port"] = new JsonArray(53), ["action"] = "route", ["outbound"] = "direct" },
            new JsonObject { ["ip_is_private"] = true, ["action"] = "route", ["outbound"] = "direct" });
        var inbound = new JsonArray(new JsonObject { ["type"] = "tun", ["tag"] = "game-tun", ["interface_name"] = AdapterName,
            ["address"] = new JsonArray(address, ipv6), ["mtu"] = 1500, ["stack"] = "mixed", ["auto_route"] = true, ["strict_route"] = false, ["dns_mode"] = "disabled",
            ["route_exclude_address"] = new JsonArray("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8") });
        if (probe != 0)
        {
            inbound.Add(new JsonObject { ["type"] = "socks", ["tag"] = "node-check", ["listen"] = "127.0.0.1", ["listen_port"] = probe,
                ["users"] = new JsonArray(new JsonObject { ["username"] = "probe", ["password"] = secret }) });
            rules.Add(new JsonObject { ["inbound"] = new JsonArray("node-check"), ["action"] = "route", ["outbound"] = "v2ray-local" });
        }
        rules.Add(new JsonObject { ["process_path"] = new JsonArray(main), ["action"] = "route", ["outbound"] = "v2ray-local" });
        var plan = new JsonObject { ["log"] = new JsonObject { ["disabled"] = true },
            ["dns"] = new JsonObject { ["servers"] = new JsonArray(new JsonObject { ["type"] = "local", ["tag"] = "system-direct" }), ["final"] = "system-direct" },
            ["inbounds"] = inbound, ["outbounds"] = new JsonArray(
                new JsonObject { ["type"] = "socks", ["tag"] = "v2ray-local", ["server"] = proxy.Host, ["server_port"] = proxy.Port, ["version"] = "5", ["bind_interface"] = loopback, ["connect_timeout"] = "10s" },
                new JsonObject { ["type"] = "direct", ["tag"] = "direct", ["bind_interface"] = physical }),
            ["route"] = new JsonObject { ["rules"] = rules, ["final"] = "direct", ["find_process"] = true, ["default_domain_resolver"] = "system-direct" },
            ["experimental"] = new JsonObject { ["clash_api"] = new JsonObject { ["external_controller"] = "127.0.0.1:" + api, ["secret"] = secret, ["default_mode"] = "rule" } } };
        if (discord is { Count: > 0 })
        {
            if (discordProbe == 0 || discord.Any(p => !Path.IsPathFullyQualified(p.Path) || Path.GetFileName(p.Path) != "Discord.exe" || excludes.Contains(p.Path, StringComparer.OrdinalIgnoreCase) || string.Equals(p.Path, main, StringComparison.OrdinalIgnoreCase))) throw new IOException("DISCORD_PROFILE_SCOPE_INVALID");
            var outbound = (JsonObject)plan["outbounds"]![0]!.DeepClone(); outbound["tag"] = "discord-media"; outbound["network"] = "udp"; plan["outbounds"]!.AsArray().Add(outbound);
            inbound.Add(new JsonObject { ["type"] = "socks", ["tag"] = "discord-check", ["listen"] = "127.0.0.1", ["listen_port"] = discordProbe,
                ["users"] = new JsonArray(new JsonObject { ["username"] = "probe", ["password"] = secret }) });
            // Only the authenticated diagnostic inbound precedes DNS direct; real application DNS remains unchanged.
            rules.Insert(0, new JsonObject { ["inbound"] = new JsonArray("discord-check"), ["network"] = "udp", ["action"] = "route", ["outbound"] = "discord-media" });
            rules.Add(new JsonObject { ["process_path"] = new JsonArray(discord.Select(p => (JsonNode?)JsonValue.Create(p.Path)).ToArray()), ["network"] = "udp", ["action"] = "route", ["outbound"] = "discord-media" });
        }
        return plan;
    }
}
