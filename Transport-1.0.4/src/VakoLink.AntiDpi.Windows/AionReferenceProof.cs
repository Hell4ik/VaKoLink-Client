using System.Security.Cryptography;
using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public sealed record AionDisorderSample(string FlowSha256, uint ProcessId, int? RelativeSequence, int OriginalBytes, bool ContentPreserved, bool ReverseCaptureOrder);
public sealed record AionReferenceProofEvidence(long OriginalsStored, long AfterPayloadCopiesStored, long MatchingSplits,
    long ReverseSplits, long OriginalSizedAfterCopies, long LimitDrops, IReadOnlyList<AionDisorderSample> Samples,
    string Scope = "Selected before originals versus after 1+(N-1) pieces within 500ms capture QPC. Capture order, NOT physical wire order. No payload/hashes/raw sequence exported. Not engine-internal counts.");

public sealed record AionFakeSample(string FlowSha256, uint ProcessId, int? OriginalRelativeSequence, int OriginalBytes,
    int FakeBytes, int SequenceDelta, int AckDelta, bool OriginalContentPreserved, bool FakeBeforeOriginalCapture,
    bool? FakeEndsBeforeSynDataOrigin);
public sealed record AionFakeProofEvidence(long OriginalsStored, long AfterPayloadCopiesStored, long OriginalsPreserved,
    long MatchingFakePairs, long FakeBeforeOriginalPairs, long UnmatchedAfterCopies, long LimitDrops,
    IReadOnlyList<AionFakeSample> Samples,
    string Scope = "One-to-one selected main flow+PID+birth before original versus after identical original and synthetic12 badseq/badack within500ms QPC. No payload/raw sequence exported. Not wire delivery, engine-internal counts or guaranteed remote rejection. After.Transport includes injected payload: use SYN-anchored Detail ACK and Before.Transport.");

public sealed class AionReferenceProof : IDisposable
{
    public bool IsKnownFake(TcpPacket p, ReadOnlySpan<byte> bytes, OwnedPacket owner, long qpc, long frequency)
    {
        if (p.PayloadLength != AionZapretResearchPlan.FakeBytes || !bytes[p.PayloadOffset..].SequenceEqual(new byte[AionZapretResearchPlan.FakeBytes])) return false;
        lock (_gate)
        {
            var key = (TcpFlowFingerprint.Flow(p.Flow), owner.Identity.ProcessId, owner.Identity.CreationTime);
            return _flows.TryGetValue(key, out var f) && f.Before.Any(o => qpc >= o.Qpc && qpc - o.Qpc <= frequency / 2
                && unchecked((int)(p.Sequence - o.Sequence)) == AionZapretResearchPlan.FakeSequenceDelta
                && unchecked((int)(p.Acknowledgment - o.Ack)) == AionZapretResearchPlan.FakeAckDelta && p.Flags == o.Flags);
        }
    }
    private sealed record Copy(uint Sequence, uint Ack, byte Flags, byte[] Bytes, long Qpc);
    private sealed class Flow { internal required string Hash; internal required uint ProcessId; internal uint? Origin; internal bool SynOrigin; internal readonly List<Copy> Before = [], After = []; }
    private readonly Dictionary<(string, uint, long), Flow> _flows = [];
    private readonly object _gate = new(); private int _bytes; private long _dropped; private bool _disposed;
    public void Observe(TcpPacket p, ReadOnlySpan<byte> bytes, OwnedPacket owner, bool before, bool outbound, long qpc)
    {
        if (!outbound) return;
        lock (_gate)
        {
            if (_disposed) return;
            var key = (TcpFlowFingerprint.Flow(p.Flow), owner.Identity.ProcessId, owner.Identity.CreationTime);
            if (!_flows.TryGetValue(key, out var f)) { if (_flows.Count >= 2) { _dropped++; return; } f = new() { Hash = key.Item1, ProcessId = key.ProcessId }; _flows[key] = f; }
            if (before && p.Flags == 2 && f.Origin is null) { f.Origin = unchecked(p.Sequence + 1); f.SynOrigin = true; }
            if (p.PayloadLength <= 0) return;
            var list = before ? f.Before : f.After;
            if (list.Count >= (before ? 256 : 768) || p.PayloadLength > 16384 || _bytes > 4 * 1024 * 1024 - p.PayloadLength) { _dropped++; return; }
            if (before) f.Origin ??= p.Sequence;
            var payload = bytes.Slice(p.PayloadOffset, p.PayloadLength).ToArray(); _bytes += payload.Length; list.Add(new(p.Sequence, p.Acknowledgment, p.Flags, payload, qpc));
        }
    }
    public AionFakeProofEvidence FakeSnapshot(long frequency)
    {
        if (frequency <= 0) throw new ArgumentOutOfRangeException(nameof(frequency));
        lock (_gate)
        {
            long preserved = 0, matches = 0, preceding = 0, unmatched = 0; var samples = new List<AionFakeSample>();
            foreach (var f in _flows.Values)
            {
                var used = new HashSet<Copy>();
                foreach (var o in f.Before)
                {
                    var copies = f.After.Where(a => !used.Contains(a) && a.Qpc >= o.Qpc && a.Qpc - o.Qpc <= frequency / 2).ToArray();
                    var original = copies.FirstOrDefault(a => a.Sequence == o.Sequence && a.Ack == o.Ack && a.Flags == o.Flags && a.Bytes.AsSpan().SequenceEqual(o.Bytes));
                    if (original is null) continue;
                    used.Add(original); preserved++;
                    var fake = copies.FirstOrDefault(a => !used.Contains(a) && a.Bytes.Length == AionZapretResearchPlan.FakeBytes
                        && a.Bytes.All(b => b == 0) && a.Flags == o.Flags
                        && unchecked((int)(a.Sequence - o.Sequence)) == AionZapretResearchPlan.FakeSequenceDelta
                        && unchecked((int)(a.Ack - o.Ack)) == AionZapretResearchPlan.FakeAckDelta);
                    if (fake is null) continue;
                    used.Add(fake); matches++; bool first = fake.Qpc < original.Qpc; if (first) preceding++;
                    int relative = unchecked((int)(o.Sequence - f.Origin!.Value));
                    bool? preSyn = f.SynOrigin ? unchecked((int)(fake.Sequence - f.Origin.Value)) + fake.Bytes.Length <= 0 : null;
                    if (samples.Count < 32) samples.Add(new(f.Hash, f.ProcessId, relative is >= 0 and <= GameTcpTracker.MaximumOffset ? relative : null,
                        o.Bytes.Length, fake.Bytes.Length, AionZapretResearchPlan.FakeSequenceDelta, AionZapretResearchPlan.FakeAckDelta, true, first, preSyn));
                }
                unmatched += f.After.Count - used.Count;
            }
            return new(_flows.Values.Sum(f => f.Before.Count), _flows.Values.Sum(f => f.After.Count), preserved, matches, preceding, unmatched, _dropped, samples);
        }
    }
    public AionReferenceProofEvidence Snapshot(long frequency)
    {
        if (frequency <= 0) throw new ArgumentOutOfRangeException(nameof(frequency));
        lock (_gate)
        {
            long matches = 0, reverse = 0, unchanged = 0; var samples = new List<AionDisorderSample>();
            foreach (var f in _flows.Values)
            {
                var used = new HashSet<Copy>();
                foreach (var o in f.Before)
                {
                    var candidates = f.After.Where(a => !used.Contains(a) && a.Qpc >= o.Qpc && a.Qpc - o.Qpc <= frequency / 2).ToArray();
                    if (candidates.Any(a => a.Sequence == o.Sequence && a.Bytes.AsSpan().SequenceEqual(o.Bytes))) unchanged++;
                    if (o.Bytes.Length < 2) continue;
                    var head = candidates.FirstOrDefault(a => a.Sequence == o.Sequence && a.Bytes.Length == 1 && a.Bytes[0] == o.Bytes[0]);
                    var tail = candidates.FirstOrDefault(a => a.Sequence == unchecked(o.Sequence + 1) && a.Bytes.AsSpan().SequenceEqual(o.Bytes.AsSpan(1)));
                    if (head is null || tail is null) continue;
                    used.Add(head); used.Add(tail);
                    matches++; bool disorder = tail.Qpc < head.Qpc; if (disorder) reverse++;
                    int offset = unchecked((int)(o.Sequence - f.Origin!.Value));
                    if (samples.Count < 32) samples.Add(new(f.Hash, f.ProcessId, offset is >= 0 and <= GameTcpTracker.MaximumOffset ? offset : null, o.Bytes.Length, true, disorder));
                }
            }
            return new(_flows.Values.Sum(f => f.Before.Count), _flows.Values.Sum(f => f.After.Count), matches, reverse, unchanged, _dropped, samples);
        }
    }
    public void Dispose()
    {
        lock (_gate) { foreach (var c in _flows.Values.SelectMany(f => f.Before.Concat(f.After))) CryptographicOperations.ZeroMemory(c.Bytes); _flows.Clear(); _disposed = true; }
    }
}
