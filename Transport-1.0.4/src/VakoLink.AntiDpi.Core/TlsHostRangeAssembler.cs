using System.Buffers.Binary;
using System.Security.Cryptography;

namespace VakoLink.AntiDpi.Core;

public sealed record TlsHostRange(int Start, int Length, TlsSniEvidence Sni);

// No packet holding/replay. Earlier ranges are already forwarded. Only structural metadata
// survives resolution; current segment must independently contain the entire verified name.
public sealed class TlsHostRangeAssembler : IDisposable
{
    private readonly byte[] _prefix = new byte[TlsClientHelloSplit.MaximumOriginalLength];
    private int _count;
    private uint _base;
    private TimeSpan? _started;
    private TlsHostRange? _absolute;
    private bool _finished;
    public bool TryCurrent(uint sequence, ReadOnlySpan<byte> payload, TimeSpan elapsed, out TlsHostRange? range, out string reason)
    {
        range = null; reason = "HOST_RANGE_WAITING";
        if (elapsed < TimeSpan.Zero || _started is { } start && (elapsed < start || elapsed - start >= TlsPrefixAssembler.MaximumLifetime))
        { reason = "HOST_RANGE_DEADLINE"; Dispose(); return false; }
        if (_absolute is not null) return Project(sequence, payload, out range, out reason);
        if (_finished) { reason = "HOST_RANGE_FINISHED"; return false; }
        if (payload.IsEmpty) { reason = "HOST_RANGE_NO_PAYLOAD"; return false; }
        if (_started is null)
        {
            if (payload[0] != 22) { reason = "HOST_RANGE_NOT_CLIENT_HELLO"; return false; }
            _started = elapsed; _base = sequence;
        }
        uint offset = unchecked(sequence - _base);
        if (offset > _count || offset > _prefix.Length || payload.Length > _prefix.Length - (int)offset)
        { reason = "HOST_RANGE_GAP_OR_LIMIT"; Dispose(); return false; }
        int at = (int)offset, overlap = Math.Min(payload.Length, _count - at);
        if (!payload[..overlap].SequenceEqual(_prefix.AsSpan(at, overlap)))
        { reason = "HOST_RANGE_CONFLICT"; Dispose(); return false; }
        payload[overlap..].CopyTo(_prefix.AsSpan(at + overlap)); _count = Math.Max(_count, at + payload.Length);
        if (!TryRead(_prefix.AsSpan(0, _count), out var found))
        {
            // An extension header split at the packet boundary is not a terminal absence of SNI.
            if (_count >= 5 && (_prefix[1] != 3 || 5 + BinaryPrimitives.ReadUInt16BigEndian(_prefix.AsSpan(3)) > _prefix.Length
                || _count >= 5 + BinaryPrimitives.ReadUInt16BigEndian(_prefix.AsSpan(3))))
            { reason = "HOST_RANGE_MALFORMED_OR_ABSENT"; Dispose(); }
            return false;
        }
        _absolute = found; CryptographicOperations.ZeroMemory(_prefix); _count = 0;
        return Project(sequence, payload, out range, out reason);
    }
    private bool Project(uint sequence, ReadOnlySpan<byte> payload, out TlsHostRange? range, out string reason)
    {
        range = null; reason = "HOST_RANGE_NOT_IN_CURRENT_SEGMENT";
        int offset = unchecked((int)(sequence - _base));
        if (offset < 0 || _absolute!.Start < offset) return false;
        int start = _absolute.Start - offset;
        if (start < 1 || start > payload.Length - _absolute.Length) return false;
        var name = payload.Slice(start, _absolute.Length);
        // Hash exact lower-case ASCII bytes as FromHost does; never trust an arbitrary supplied cut.
        var lower = name.ToArray();
        foreach (var b in lower) if (!(b is >= 65 and <= 90 or >= 97 and <= 122 or >= 48 and <= 57 or 45 or 46))
            { reason = "HOST_RANGE_CURRENT_BYTES_CHANGED"; CryptographicOperations.ZeroMemory(lower); return false; }
        for (int i = 0; i < lower.Length; i++) if (lower[i] is >= 65 and <= 90) lower[i] += 32;
        bool same = Convert.ToHexString(SHA256.HashData(lower)) == _absolute.Sni.HostSha256;
        CryptographicOperations.ZeroMemory(lower);
        if (!same) { reason = "HOST_RANGE_CURRENT_BYTES_CHANGED"; return false; }
        range = _absolute with { Start = start }; reason = "HOST_RANGE_STRUCTURAL_CURRENT_SEGMENT"; return true;
    }
    public static bool TryRead(ReadOnlySpan<byte> bytes, out TlsHostRange? range)
    {
        range = null;
        if (!TlsClientHelloSplit.TryFindSplit(bytes, out int cut, out _, out var sni, true) || sni is null) return false;
        int at = 43; at += 1 + bytes[at]; at += 2 + BinaryPrimitives.ReadUInt16BigEndian(bytes[at..]); at += 1 + bytes[at]; at += 2;
        while (at + 4 <= bytes.Length)
        {
            int type = BinaryPrimitives.ReadUInt16BigEndian(bytes[at..]), count = BinaryPrimitives.ReadUInt16BigEndian(bytes[(at + 2)..]); at += 4;
            if (count > bytes.Length - at) return false;
            if (type == 0)
            {
                int length = BinaryPrimitives.ReadUInt16BigEndian(bytes[(at + 3)..]);
                if (length < 3 || length + 5 != count || cut != at + 5 + Math.Max(1, length / 2)) return false;
                range = new(at + 5, length, sni); return true;
            }
            at += count;
        }
        return false;
    }
    public void Dispose() { CryptographicOperations.ZeroMemory(_prefix); _count = 0; _absolute = null; _finished = true; }
}
