using System.Buffers.Binary;
using System.Security.Cryptography;

namespace VakoLink.AntiDpi.Core;

// Passive diagnostic only, never packet holding/replay or a source of authorization.
// true means extension PRESENT (possibly GREASE), not ECH negotiation or known inner hostname.
public sealed class TlsExtensionObserver : IDisposable
{
    private readonly byte[] _bytes = new byte[TlsClientHelloSplit.MaximumOriginalLength];
    private uint _sequence;
    private int _count;
    private TimeSpan? _started;
    private bool _finished;
    public bool? EchExtensionObserved { get; private set; }
    public void Observe(uint sequence, ReadOnlySpan<byte> payload, TimeSpan elapsed)
    {
        if (_finished) return;
        if (elapsed < TimeSpan.Zero || _started is { } started && (elapsed < started || elapsed - started >= TlsPrefixAssembler.MaximumLifetime))
        { Dispose(); return; }
        if (_started is null)
        {
            if (payload.Length == 0 || payload[0] != 22) return;
            _started = elapsed; _sequence = sequence;
        }
        var offset = unchecked(sequence - _sequence);
        if (offset > _count || payload.Length > _bytes.Length - (long)offset) { Dispose(); return; }
        int at = (int)offset, overlap = Math.Min(payload.Length, _count - at);
        if (!payload[..overlap].SequenceEqual(_bytes.AsSpan(at, overlap))) { Dispose(); return; }
        payload[overlap..].CopyTo(_bytes.AsSpan(at + overlap)); _count = Math.Max(_count, at + payload.Length);
        if (_count < 9) return;
        int record = 5 + BinaryPrimitives.ReadUInt16BigEndian(_bytes.AsSpan(3));
        if (record is < 9 or > TlsClientHelloSplit.MaximumOriginalLength) { Dispose(); return; }
        if (_count < record) return;
        EchExtensionObserved = Inspect(_bytes.AsSpan(0, record)); Dispose();
    }
    public static bool? Inspect(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 52 || payload.Length > TlsClientHelloSplit.MaximumOriginalLength || payload[0] != 22 || payload[1] != 3 || payload[5] != 1) return null;
        int record = 5 + BinaryPrimitives.ReadUInt16BigEndian(payload[3..]);
        int end = 9 + ((payload[6] << 16) | (payload[7] << 8) | payload[8]);
        if (record > payload.Length || end > record || end < 47) return null;
        int at = 43; at += 1 + payload[at];
        if (at + 2 > end) return null;
        var ciphers = BinaryPrimitives.ReadUInt16BigEndian(payload[at..]); at += 2 + ciphers;
        if (ciphers < 2 || (ciphers & 1) != 0 || at >= end) return null;
        var compression = payload[at++]; at += compression;
        if (compression == 0 || at + 2 > end) return null;
        int extensions = BinaryPrimitives.ReadUInt16BigEndian(payload[at..]); at += 2;
        if (at + extensions != end) return null;
        bool ech = false;
        while (at < end)
        {
            if (at + 4 > end) return null;
            var type = BinaryPrimitives.ReadUInt16BigEndian(payload[at..]); var length = BinaryPrimitives.ReadUInt16BigEndian(payload[(at + 2)..]); at += 4;
            if (at + length > end) return null;
            if (type == 0xFE0D) ech = true;
            at += length;
        }
        return ech;
    }
    public void Dispose() { CryptographicOperations.ZeroMemory(_bytes); _count = 0; _finished = true; }
}
