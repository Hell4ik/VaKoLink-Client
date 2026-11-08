using System.Text.Json;
using System.Text.Json.Nodes;

namespace VakoLink.AntiDpi.Windows;

// Passive API metadata only. This history NEVER authorizes routing or packet modification.
public sealed class MediaTimeline
{
    private sealed record State(long Up, long Down, DateTimeOffset First, DateTimeOffset Last, DateTimeOffset LastUp, DateTimeOffset LastDown, string TupleHash);
    private readonly Dictionary<string, State> _flows = new(); private readonly object _gate = new();
    private readonly string _folder; private int _chunk; private long _samples, _evicted, _writeErrors;
    public MediaTimeline(string folder) { _folder = folder; TunPrivateStore.EnsurePrivate(folder); }
    public void Record(string kind, object data)
    {
        lock (_gate) try
        {
            string file = Path.Combine(_folder, $"media-{_chunk % 8:D2}.jsonl");
            if (File.Exists(file) && new FileInfo(file).Length > 4 * 1024 * 1024) { _chunk++; file = Path.Combine(_folder, $"media-{_chunk % 8:D2}.jsonl"); File.WriteAllText(file, ""); }
            File.AppendAllText(file, JsonSerializer.Serialize(new { Utc = DateTimeOffset.UtcNow, Kind = kind, Data = data }) + "\n");
        }
        catch { _writeErrors++; }
    }
    public void Sample(JsonArray connections, IReadOnlyList<DiscordComponentPin> pins, string game, DateTimeOffset now, double apiLatencyMs)
    {
        lock (_gate)
        {
            var seen = new HashSet<string>(); var samples = new List<object>();
            foreach (var node in connections.Take(1024))
            {
                var m = node!["metadata"]!; string path = AionTunPlan.CanonicalProcess((string?)m["processPath"] ?? "");
                bool discord = string.Equals(Path.GetFileName(path), "Discord.exe", StringComparison.OrdinalIgnoreCase), aion = string.Equals(path, game, StringComparison.OrdinalIgnoreCase);
                if (!discord && !aion) continue;
                string id = AionTunPlan.Hash((string)node["id"]!); seen.Add(id);
                var tuple = new JsonArray(m["sourceIP"]?.DeepClone(), m["sourcePort"]?.DeepClone(), m["destinationIP"]?.DeepClone(), m["destinationPort"]?.DeepClone(), m["network"]?.DeepClone());
                string tupleHash = AionTunPlan.Hash(tuple.ToJsonString()); long up = (long?)node["upload"] ?? 0, down = (long?)node["download"] ?? 0;
                if (!_flows.TryGetValue(id, out var old)) old = new(0, 0, now, now, now, now, tupleHash);
                if (_flows.Count >= 256 && !_flows.ContainsKey(id)) { _flows.Remove(_flows.MinBy(kv => kv.Value.Last).Key); _evicted++; }
                bool reset = up < old.Up || down < old.Down || tupleHash != old.TupleHash;
                var next = new State(up, down, old.First, now, up != old.Up ? now : old.LastUp, down != old.Down ? now : old.LastDown, tupleHash); _flows[id] = next;
                samples.Add(new { Id = id, Component = discord ? "Discord.exe" : "AION2.exe", ApprovedDiscordPath = pins.Any(p => string.Equals(p.Path, path, StringComparison.OrdinalIgnoreCase)),
                    Network = (string?)m["network"], Family = ((string?)m["destinationIP"])?.Contains(':') == true ? "IPv6" : "IPv4OrHostname", TupleSha256 = tupleHash,
                    DestinationSha256 = AionTunPlan.Hash((string?)m["destinationIP"] ?? (string?)m["host"] ?? "unknown"), Port = m["destinationPort"]?.DeepClone(),
                    LocalPort = m["sourcePort"]?.DeepClone(), Chains = node["chains"]?.DeepClone(), Up = up, Down = down, DeltaUp = reset ? (long?)null : up - old.Up, DeltaDown = reset ? (long?)null : down - old.Down,
                    CounterOrTupleReset = reset, First = old.First, LastUp = next.LastUp, LastDown = next.LastDown, NoInboundProgressMs = (now - next.LastDown).TotalMilliseconds,
                    NoOutboundProgressMs = (now - next.LastUp).TotalMilliseconds });
            }
            foreach (var missing in _flows.Where(kv => !seen.Contains(kv.Key) && now - kv.Value.Last > TimeSpan.FromSeconds(2)).ToArray())
            { Record("ApiFlowNoLongerVisible_NotTcpCloseProof", new { Id = missing.Key, missing.Value.Last, missing.Value.LastDown }); _flows.Remove(missing.Key); }
            _samples++; Record("FlowSample", new { SampleUtc = now, ApiLatencyMs = apiLatencyMs, Flows = samples,
                Limits = "API byte counters, NOT packet/ACK counters or RTP sequence; silence not proof of loss; no decrypted Gateway/auth/DAVE/queue metrics" });
        }
    }
    public object Evidence { get { lock (_gate) return new { Samples = _samples, EvictedFlows = _evicted, WriteErrors = _writeErrors, ChunksWritten = _chunk + 1, RetainedChunks = 8, MaxChunkBytes = 4 * 1024 * 1024, ActiveTracked = _flows.Count, ConnectionMetadataOnly = true }; } }
}
