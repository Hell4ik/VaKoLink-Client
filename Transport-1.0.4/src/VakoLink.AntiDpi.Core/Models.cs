namespace VakoLink.AntiDpi.Core;

public sealed record AppProfile(string Id, string DisplayName, string ExecutablePath, string StrategyId);

public sealed record ScenarioDefinition(string Id, string DisplayName, IReadOnlyList<string> ProfileIds);

public enum StrategyMode
{
    Observe,
    UdpFakeTtl,
    UdpFakeBadChecksum,
    TlsSplit,
    TlsSplitUdpFakeTtl,
    TlsDisorder,
    TlsDisorderUdpFakeTtl,
    TlsFakeBadSequenceSplit,
    TlsHostFakeTimestamp,
}

public sealed record StrategyDefinition(
    string Id,
    string DisplayName,
    StrategyMode Mode,
    byte Ttl,
    int Repeats,
    int InitialPackets);

/// <summary>Small, explicit strategy set; these strategies are candidates, not verified fixes.</summary>
public static class StrategyCatalog
{
    public const int MaximumPacketSize = 1200;
    public const int MaximumRepeats = 3;
    public const int MaximumInitialPackets = 2;

    public static IReadOnlyList<StrategyDefinition> All { get; } = Array.AsReadOnly(
    [
        new StrategyDefinition("observe", "Наблюдение — без изменения трафика", StrategyMode.Observe, 0, 0, 0),
        new StrategyDefinition("udp-fake-ttl2", "Эксперимент: UDP fake TTL 2", StrategyMode.UdpFakeTtl, 2, 3, 2),
        new StrategyDefinition("udp-fake-ttl3", "Эксперимент: UDP fake TTL 3", StrategyMode.UdpFakeTtl, 3, 3, 2),
        new StrategyDefinition("udp-fake-bad-checksum", "Эксперимент: UDP fake с неверной checksum", StrategyMode.UdpFakeBadChecksum, 64, 3, 2),
        new StrategyDefinition("discord-tls-split", "Кандидат: Discord TLS SNI split (TCP)", StrategyMode.TlsSplit, 0, 0, 0),
        new StrategyDefinition("discord-tls-split-udp-ttl2", "Кандидат: Discord TLS split + UDP TTL 2", StrategyMode.TlsSplitUdpFakeTtl, 2, 3, 2),
        new StrategyDefinition("discord-tls-disorder", "Кандидат: Discord TLS 3 сегмента в обратном порядке", StrategyMode.TlsDisorder, 0, 0, 0),
        new StrategyDefinition("discord-tls-disorder-udp-ttl2", "Кандидат: Discord TLS disorder + UDP TTL 2", StrategyMode.TlsDisorderUdpFakeTtl, 2, 3, 2),
        new StrategyDefinition("discord-tls-fake-seq-split", "Кандидат: TLS fake вне окна + упорядоченный SNI split", StrategyMode.TlsFakeBadSequenceSplit, 0, 0, 0),
        new StrategyDefinition("discord-hostfake-ts", "Discord: host-range fake с TS guard + ECH outer coverage", StrategyMode.TlsHostFakeTimestamp, 0, 0, 0),
        new StrategyDefinition("discord-hostfake-range-ts", "R4.6: структурный SNI диапазон, включая последующий TCP-сегмент", StrategyMode.TlsHostFakeTimestamp, 0, 0, 0),
    ]);

    public static StrategyDefinition Get(string id) =>
        All.FirstOrDefault(strategy => string.Equals(strategy.Id, id, StringComparison.Ordinal))
        ?? throw new ArgumentException("Unknown strategy identifier.", nameof(id));

    public static void Validate(StrategyDefinition strategy)
    {
        ArgumentNullException.ThrowIfNull(strategy);
        if (strategy.Mode is StrategyMode.Observe or StrategyMode.TlsSplit or StrategyMode.TlsDisorder or StrategyMode.TlsFakeBadSequenceSplit or StrategyMode.TlsHostFakeTimestamp)
        {
            if (strategy.Ttl != 0 || strategy.Repeats != 0 || strategy.InitialPackets != 0)
            {
                throw new ArgumentException("Observe must not have a packet injection budget.", nameof(strategy));
            }

            return;
        }

        if (strategy.Mode is not (StrategyMode.UdpFakeTtl or StrategyMode.UdpFakeBadChecksum or StrategyMode.TlsSplitUdpFakeTtl or StrategyMode.TlsDisorderUdpFakeTtl)
            || strategy.Repeats is < 1 or > MaximumRepeats
            || strategy.InitialPackets is < 1 or > MaximumInitialPackets
            || (strategy.Mode is StrategyMode.UdpFakeTtl or StrategyMode.TlsSplitUdpFakeTtl or StrategyMode.TlsDisorderUdpFakeTtl && strategy.Ttl is < 1 or > 3)
            || (strategy.Mode == StrategyMode.UdpFakeBadChecksum && strategy.Ttl == 0))
        {
            throw new ArgumentException("Strategy exceeds the bounded experimental contract.", nameof(strategy));
        }
    }

    public static bool HasTls(StrategyDefinition strategy) => strategy.Mode is StrategyMode.TlsSplit or StrategyMode.TlsSplitUdpFakeTtl or StrategyMode.TlsDisorder or StrategyMode.TlsDisorderUdpFakeTtl or StrategyMode.TlsFakeBadSequenceSplit or StrategyMode.TlsHostFakeTimestamp;
    public static bool HasTlsFake(StrategyDefinition strategy) => strategy.Mode is StrategyMode.TlsFakeBadSequenceSplit or StrategyMode.TlsHostFakeTimestamp;
    public static bool IsHostFake(StrategyDefinition strategy) => strategy.Mode == StrategyMode.TlsHostFakeTimestamp;
    public static bool IsStructuralHostFake(StrategyDefinition strategy) => strategy.Id == "discord-hostfake-range-ts";
    public static bool HasUdp(StrategyDefinition strategy) => strategy.Mode is StrategyMode.UdpFakeTtl or StrategyMode.UdpFakeBadChecksum or StrategyMode.TlsSplitUdpFakeTtl or StrategyMode.TlsDisorderUdpFakeTtl;
    public static bool IsDisorder(StrategyDefinition strategy) => strategy.Mode is StrategyMode.TlsDisorder or StrategyMode.TlsDisorderUdpFakeTtl;
    public static int TlsSegmentCount(StrategyDefinition strategy) => !HasTls(strategy) ? 0 : IsDisorder(strategy) || IsHostFake(strategy) ? 3 : 2;
}
