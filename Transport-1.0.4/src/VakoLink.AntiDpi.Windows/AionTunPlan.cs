using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace VakoLink.AntiDpi.Windows;

public static class AionTunPlan
{
    public const string Version = "1.0.0-aion-transport", AdapterName = "VakoLink Aion Experiment";
    // Transport binding is separate from the frozen, older direct AntiDPI experiments.
    public const string ClientSha256 = "699F42CD268DAD447DC560162358D0C5EA1A4C27A36BE3F66AC5557047DDAFD8";
    public const string CapsuleFile = "germany.dpapi";
    public sealed record PinEvidence(string ExpectedCoreSha256, string ObservedCoreSha256, string ExpectedMainSha256,
        string ObservedMainSha256, bool NcSignatureTrusted, bool MainPathMatches, bool CapsulePinsMatch);
    public static string? PinFailure(PinEvidence p) => p.ExpectedCoreSha256 != p.ObservedCoreSha256 ? "TUN_CORE_HASH_CHANGED"
        : p.ExpectedMainSha256 != p.ObservedMainSha256 ? "TUN_AION_IMAGE_CHANGED"
        : !p.NcSignatureTrusted ? "TUN_AION_SIGNATURE_UNTRUSTED" : !p.MainPathMatches ? "TUN_AION_PATH_CHANGED"
        : !p.CapsulePinsMatch ? "TUN_CAPSULE_BINDING_CHANGED" : null;
    public static string FailureMessage(string? code) => code switch
    {
        "TUN_AION_IMAGE_CHANGED" => "AION2.exe изменился после подготовки сборки. Транспорт не разрешён; нужна проверка обновлённого подписанного клиента.",
        "TUN_CORE_HASH_CHANGED" => "Файл sing-box отличается от проверенной версии. Запуск заблокирован.",
        "TUN_AION_SIGNATURE_UNTRUSTED" => "Подпись клиента NC Corporation не прошла проверку.",
        "TUN_AION_PATH_CHANGED" or "TUN_CAPSULE_BINDING_CHANGED" => "Привязка защищённой конфигурации к клиенту/ядру не совпала.",
        "TUN_CORE_EXITED_BEFORE_API" => "Ядро самостоятельно завершилось до готовности API; смотрите exit code и безопасную диагностику отчёта.",
        "TUN_CORE_API_NOT_READY" => "Ядро не подтвердило готовность локального API за 15 секунд; контроллер остановил запуск.",
        "TUN_PREFLIGHT_CONFLICT" => "Недостаточно прав либо игра/другой перехват уже запущены. Закройте их штатно.",
        _ => "Ошибка транспорта; точный код: " + (code ?? "UNKNOWN")
    };
    public const string CoreSha256 = "7BBEF1DEA9189EE12799AE834EA4B4658355DA25C47A21AD8804904C0CCD9410";
    public const string CoreVersion = "1.14.2";
    public static string CorePath => Path.Combine(AppContext.BaseDirectory, "core", "sing-box.exe");
    public const string RuntimePath = @"C:\Program Files\v2rayN\binConfigs\config.json";
    public const string SourceRuntimeSha256 = "FDBCD82A760AB1A6733BB2CAB35A11A112F5D8BCAF5B79FD237303EAD9D2BA03";
    public static string Hash(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
    public static string FileHash(string path) { using var f = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(f)); }
    public static JsonObject Import(string raw)
    {
        var c = JsonNode.Parse(raw) ?? throw new InvalidDataException("NODE_CONFIG_REQUIRED");
        var candidates = c["outbounds"]!.AsArray().Where(n => (string?)n?["tag"] == "proxy").ToArray();
        if (candidates.Length != 1) throw new InvalidDataException("NODE_PROXY_NOT_UNIQUE");
        var n = candidates[0]!; var stream = n["streamSettings"]!;
        if ((string?)n["protocol"] != "vless" || (string?)stream["security"] != "reality" || (string?)stream["network"] is not ("raw" or "tcp")
            || (bool?)n["mux"]?["enabled"] == true || stream["tcpSettings"] is not null || stream["rawSettings"] is not null) throw new InvalidDataException("NODE_TRANSPORT_UNSUPPORTED");
        var next = n["settings"]!["vnext"]!.AsArray(); if (next.Count != 1 || next[0]!["users"]!.AsArray().Count != 1) throw new InvalidDataException("NODE_ENDPOINT_NOT_UNIQUE");
        var v = next[0]!; var u = v["users"]![0]!; var r = stream["realitySettings"]!;
        if (!IPAddress.TryParse((string?)v["address"], out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
            || !Guid.TryParse((string?)u["id"], out _) || (int?)v["port"] is not (> 0 and <= 65535) || (string?)u["flow"] != "xtls-rprx-vision"
            || !string.IsNullOrWhiteSpace((string?)r["mldsa65Verify"]) || string.IsNullOrWhiteSpace((string?)r["publicKey"])) throw new InvalidDataException("NODE_PARAMETERS_UNSUPPORTED");
        return new JsonObject
        {
            ["type"] = "vless",
            ["tag"] = "germany",
            ["server"] = ip.ToString(),
            ["server_port"] = (int)v["port"]!,
            ["uuid"] = (string?)u["id"],
            ["flow"] = (string?)u["flow"],
            ["packet_encoding"] = "xudp",
            ["tls"] = new JsonObject
            {
                ["enabled"] = true,
                ["server_name"] = (string?)r["serverName"],
                ["insecure"] = false,
                ["utls"] = new JsonObject { ["enabled"] = true, ["fingerprint"] = (string?)r["fingerprint"] },
                ["reality"] = new JsonObject { ["enabled"] = true, ["public_key"] = (string?)r["publicKey"], ["short_id"] = (string?)r["shortId"] }
            }
        };
    }
    public static JsonObject Build(JsonObject node, string mainPath, string physicalInterface, int apiPort, string apiSecret, int probePort = 0)
    {
        if (!Path.IsPathFullyQualified(mainPath) || Path.GetFileName(mainPath) != "AION2.exe" || string.IsNullOrWhiteSpace(physicalInterface)
            || apiPort is < 1024 or > 65535 || apiSecret.Length != 64) throw new ArgumentException("TUN_PLAN_ARGUMENTS");
        var outbound = (JsonObject)node.DeepClone(); outbound["bind_interface"] = physicalInterface;
        var inbounds = new JsonArray(new JsonObject
        {
            ["type"] = "tun",
            ["tag"] = "aion-tun",
            ["interface_name"] = AdapterName,
            ["address"] = new JsonArray("172.29.219.1/30", "fd94:61e9:7b13::1/126"),
            ["mtu"] = 1500,
            ["stack"] = "mixed",
            ["auto_route"] = true,
            ["strict_route"] = false,
            ["dns_mode"] = "disabled",
            ["route_exclude_address"] = new JsonArray((string)node["server"]! + "/32", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8")
        });
        var rules = new JsonArray(new JsonObject { ["port"] = new JsonArray(53), ["action"] = "route", ["outbound"] = "direct" },
            new JsonObject { ["process_path"] = new JsonArray(CorePath), ["action"] = "route", ["outbound"] = "direct" },
            new JsonObject { ["ip_is_private"] = true, ["action"] = "route", ["outbound"] = "direct" });
        // Probe override is confined to an authenticated loopback inbound and ONLY technical lifecycle mode.
        if (probePort != 0)
        {
            inbounds.Add(new JsonObject
            {
                ["type"] = "socks",
                ["tag"] = "node-check",
                ["listen"] = "127.0.0.1",
                ["listen_port"] = probePort,
                ["users"] = new JsonArray(new JsonObject { ["username"] = "probe", ["password"] = apiSecret })
            });
            rules.Add(new JsonObject { ["inbound"] = new JsonArray("node-check"), ["action"] = "route", ["outbound"] = "germany" });
        }
        rules.Add(new JsonObject { ["process_path"] = new JsonArray(mainPath), ["action"] = "route", ["outbound"] = "germany" });
        return new JsonObject
        {
            ["log"] = new JsonObject { ["disabled"] = true },
            ["dns"] = new JsonObject { ["servers"] = new JsonArray(new JsonObject { ["type"] = "local", ["tag"] = "system-direct" }), ["final"] = "system-direct" },
            ["inbounds"] = inbounds,
            ["outbounds"] = new JsonArray(outbound, new JsonObject { ["type"] = "direct", ["tag"] = "direct", ["bind_interface"] = physicalInterface }),
            ["route"] = new JsonObject { ["rules"] = rules, ["final"] = "direct", ["default_interface"] = physicalInterface, ["auto_detect_interface"] = false, ["find_process"] = true, ["default_domain_resolver"] = "system-direct" },
            ["experimental"] = new JsonObject { ["clash_api"] = new JsonObject { ["external_controller"] = "127.0.0.1:" + apiPort, ["secret"] = apiSecret, ["default_mode"] = "rule" } }
        };
    }
    public static string CanonicalProcess(string path)
    { int suffix = path.LastIndexOf(" (", StringComparison.Ordinal); return suffix > 0 && path.EndsWith(')') ? path[..suffix] : path; }
}
