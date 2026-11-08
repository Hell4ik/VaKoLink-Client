using System.Text.Json.Nodes;

namespace VakoLink.AntiDpi.Windows;

public sealed record BaselineStabilityCheck(int Snapshot, bool Stable, IReadOnlyDictionary<string, bool> PreviousComparison,
    IReadOnlyList<NetworkCategoryDifference> Differences);
public static class ProxyBaselineStability
{
    public const int MaximumSnapshots = 3;
    public static async Task<JsonObject> CaptureAsync(Func<Task<JsonObject>> snapshot, Action<BaselineStabilityCheck> record)
    {
        var previous = await snapshot();
        for (int ordinal = 2; ordinal <= MaximumSnapshots; ordinal++)
        {
            var current = await snapshot(); var comparison = ProxyTunSession.Compare(previous, current);
            bool stable = comparison.Values.All(v => v);
            record(new(ordinal, stable, comparison, ProxyNetworkIsolation.DescribeChanges(previous, current)));
            if (stable) return current;
            previous = current;
        }
        throw new IOException("TUN_BASELINE_NOT_SETTLED");
    }
}
