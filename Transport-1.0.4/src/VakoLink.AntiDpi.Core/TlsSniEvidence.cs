using System.Security.Cryptography;
using System.Text;

namespace VakoLink.AntiDpi.Core;

// No arbitrary hostname, endpoints or payload exported. Exact names only from this fixed public catalog.
public sealed record TlsSniEvidence(string Root, string KnownHost, string HostSha256)
{
    private static readonly string[] Roots = ["discord.com", "discordapp.com", "discord.gg", "discord.media", "discordapp.net"];
    private static readonly string[] Known = ["discord.com", "discordapp.com", "gateway.discord.gg", "cdn.discordapp.com",
        "media.discordapp.net", "updates.discord.com", "dl.discordapp.net", "discord.gg", "discord.media", "discordapp.net", "cloudflare-ech.com"];
    public static TlsSniEvidence FromHost(string host)
    {
        var normalized = host.ToLowerInvariant();
        return new(Roots.FirstOrDefault(root => normalized == root || normalized.EndsWith("." + root, StringComparison.Ordinal)) ?? "OTHER",
            Known.Contains(normalized, StringComparer.Ordinal) ? normalized : "REDACTED",
            Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(normalized))));
    }
    public static bool IsSafe(TlsSniEvidence evidence) => evidence is not null
        && (evidence.Root == "OTHER" || Roots.Contains(evidence.Root, StringComparer.Ordinal))
        && (evidence.KnownHost == "REDACTED" || Known.Contains(evidence.KnownHost, StringComparer.Ordinal))
        && evidence.HostSha256 is { Length: 64 } && evidence.HostSha256.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');
}
