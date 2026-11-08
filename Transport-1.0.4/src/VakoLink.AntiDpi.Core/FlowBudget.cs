namespace VakoLink.AntiDpi.Core;

/// <summary>
/// One fixed sixty-second budget per exact flow. Packet arrivals and strategy changes cannot reset it.
/// Full tables refuse new flows; expiration is the only way to reclaim entries.
/// </summary>
public sealed class FlowBudget
{
    public const int MaximumCapacity = 4096;
    public static TimeSpan Expiration { get; } = TimeSpan.FromSeconds(60);

    private readonly int capacity;
    private readonly Dictionary<FlowKey, Entry> entries = [];
    private readonly object gate = new();

    public FlowBudget(int maximumEntries = MaximumCapacity)
    {
        if (maximumEntries is < 1 or > MaximumCapacity)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumEntries));
        }

        capacity = maximumEntries;
    }

    public int Count
    {
        get
        {
            lock (gate)
            {
                return entries.Count;
            }
        }
    }

    public bool TryConsume(FlowKey flow, string strategyId, DateTimeOffset now, int initialPackets)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(strategyId);
        if (initialPackets is < 1 or > StrategyCatalog.MaximumInitialPackets)
        {
            throw new ArgumentOutOfRangeException(nameof(initialPackets));
        }

        lock (gate)
        {
            // Table size has a hard upper bound; removal does not require an unbounded secondary index.
            foreach (var expired in entries.Where(pair => pair.Value.ExpiresAt <= now).Select(pair => pair.Key).ToArray())
            {
                entries.Remove(expired);
            }

            if (entries.TryGetValue(flow, out var entry))
            {
                if (!string.Equals(entry.StrategyId, strategyId, StringComparison.Ordinal)
                    || entry.Consumed >= Math.Min(entry.Limit, initialPackets))
                {
                    return false;
                }

                entries[flow] = entry with { Consumed = entry.Consumed + 1 };
                return true;
            }

            if (entries.Count >= capacity)
            {
                return false;
            }

            entries.Add(flow, new Entry(strategyId, now + Expiration, initialPackets, 1));
            return true;
        }
    }

    private sealed record Entry(string StrategyId, DateTimeOffset ExpiresAt, int Limit, int Consumed);
}
