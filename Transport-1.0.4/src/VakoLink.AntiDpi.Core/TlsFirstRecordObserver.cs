using System.Security.Cryptography;

namespace VakoLink.AntiDpi.Core;

// Only first 9 bytes, never TLS decryption. Header may be split across TCP segments.
public sealed class TlsFirstRecordObserver : IDisposable
{
    private readonly byte[] _prefix = new byte[9]; private uint _sequence; private int _count; private TimeSpan? _started; private bool _finished;
    public bool? ServerHelloPrefix { get; private set; }
    public void Observe(uint sequence, ReadOnlySpan<byte> payload, TimeSpan elapsed)
    {
        if (_finished || payload.IsEmpty) return;
        if (_started is { } start && (elapsed < start || elapsed - start >= TlsPrefixAssembler.MaximumLifetime)) { Dispose(); return; }
        if (_started is null) { _started = elapsed; _sequence = sequence; }
        var offset = unchecked(sequence - _sequence); if (offset > _count) { Dispose(); return; }
        int at = (int)offset, take = Math.Min(payload.Length, 9 - at), overlap = Math.Min(take, _count - at);
        if (!payload[..overlap].SequenceEqual(_prefix.AsSpan(at, overlap))) { Dispose(); return; }
        payload.Slice(overlap, take - overlap).CopyTo(_prefix.AsSpan(at + overlap)); _count = Math.Max(_count, at + take);
        if (_count < 9) return;
        ServerHelloPrefix = _prefix[0] == 22 && _prefix[1] == 3 && _prefix[5] == 2; Dispose();
    }
    public void Dispose() { CryptographicOperations.ZeroMemory(_prefix); _finished = true; }
}
