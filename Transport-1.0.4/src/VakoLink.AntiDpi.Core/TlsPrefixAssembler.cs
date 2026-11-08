using System.Security.Cryptography;

namespace VakoLink.AntiDpi.Core;

// Bounded, passive prefix reconstruction: earlier TCP segments have ALREADY been forwarded.
// Never delays, replays or changes them. No content is exported. One endpoint/identity per instance.
public sealed class TlsPrefixAssembler : IDisposable
{
    public static readonly TimeSpan MaximumLifetime = TimeSpan.FromSeconds(3);
    private readonly byte[] _prefix = new byte[TlsClientHelloSplit.MaximumOriginalLength];
    private uint _firstSequence;
    private int _count;
    private TimeSpan? _started;
    private bool _disposed;
    private uint _resolvedSequence;
    private int _resolvedLength, _resolvedSplit;
    private byte[]? _resolvedHash;
    public TlsSniEvidence? Sni { get; private set; }
    public bool TryFindCurrentSplit(uint sequence, ReadOnlySpan<byte> payload, TimeSpan elapsed,
        out int split, out string reason, bool diagnosticAnyHost = false)
    {
        split = 0; reason = "TLS_PREFIX_WAITING";
        if (elapsed < TimeSpan.Zero || _started is { } started && (elapsed < started || elapsed - started >= MaximumLifetime))
        { reason = "TLS_PREFIX_DEADLINE"; Dispose(); return false; }
        if (_disposed)
        {
            // After success only retain a SHA/cut marker, never content. The outer per-endpoint budget still applies.
            if (_resolvedHash is not null && sequence == _resolvedSequence && payload.Length == _resolvedLength
                && CryptographicOperations.FixedTimeEquals(SHA256.HashData(payload), _resolvedHash))
            { split = _resolvedSplit; reason = "TLS_PREFIX_RESOLVED_RETRANSMISSION"; return true; }
            reason = "TLS_PREFIX_FINISHED"; return false;
        }
        if (_started is null)
        {
            if (payload.Length == 0 || payload[0] != 22) { reason = "NOT_CLIENT_HELLO_PREFIX"; return false; }
            _started = elapsed; _firstSequence = sequence;
        }
        var offset = unchecked(sequence - _firstSequence);
        if (offset > _count || offset > _prefix.Length || payload.Length > _prefix.Length - (int)offset)
        { reason = "TLS_PREFIX_GAP_OR_LIMIT"; Dispose(); return false; }
        int at = (int)offset;
        int overlap = Math.Min(payload.Length, _count - at);
        if (!payload[..overlap].SequenceEqual(_prefix.AsSpan(at, overlap)))
        { reason = "TLS_PREFIX_CONFLICT"; Dispose(); return false; }
        payload[overlap..].CopyTo(_prefix.AsSpan(at + overlap));
        _count = Math.Max(_count, at + payload.Length);
        if (!TlsClientHelloSplit.TryFindSplit(_prefix.AsSpan(0, _count), out var absolute, out reason, out var sni, diagnosticAnyHost))
        {
            Sni = sni ?? Sni;
            if (reason != "NOT_COMPLETE_CLIENT_HELLO") Dispose();
            else reason = overlap == payload.Length ? "TLS_PREFIX_IDENTICAL_RETRANSMISSION" : "TLS_PREFIX_WAITING";
            return false;
        }
        Sni = sni;
        split = absolute - at;
        Dispose();
        if (split <= 1 || split >= payload.Length)
        { split = 0; reason = "TLS_PREFIX_CUT_ALREADY_FORWARDED"; return false; }
        _resolvedSequence = sequence; _resolvedLength = payload.Length; _resolvedSplit = split;
        _resolvedHash = SHA256.HashData(payload);
        reason = "TLS_PREFIX_CURRENT_SEGMENT_SNI_SPLIT"; return true;
    }
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_prefix); _count = 0; _disposed = true;
        if (_resolvedHash is not null) CryptographicOperations.ZeroMemory(_resolvedHash);
        _resolvedHash = null;
    }
}
