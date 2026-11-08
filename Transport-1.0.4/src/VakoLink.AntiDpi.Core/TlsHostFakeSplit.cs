using System.Buffers.Binary;
using System.Text;

namespace VakoLink.AntiDpi.Core;

public sealed record TcpWireStep(byte[] Packet, bool Synthetic);

// Independently implemented bounded host-range fake; not an ALT13 clone or copied fake template.
public static class TlsHostFakeSplit
{
    public const uint TimestampAge = 600_000;
    public static bool Allowed(TlsSniEvidence? sni) => sni is not null &&
        (sni.Root != "OTHER" || sni.KnownHost == "cloudflare-ech.com");

    public static bool TryBuild(byte[] original, out IReadOnlyList<TcpWireStep> steps, out string reason, bool localhostFixture = false)
    {
        steps = []; reason = "HOSTFAKE_UNSUPPORTED_CURRENT_SEGMENT";
        if (!TcpPacket.TryParse(original, out var tcp) || tcp is null || original.Length > TlsClientHelloSplit.MaximumOriginalLength
            || tcp.Flags is not (0x10 or 0x18)) return false;
        var payload = original.AsSpan(tcp.PayloadOffset);
        if (!TlsClientHelloSplit.TryFindSplit(payload, out var cut, out _, out var sni, true)
            || !(Allowed(sni) || localhostFixture && sni?.HostSha256 == TlsSniEvidence.FromHost("localhost").HostSha256)) return false;
        // No guessed/cross-segment hostname ranges. Unsupported noncatalogued names pass unchanged.
        var host = localhostFixture ? "localhost" : sni!.KnownHost;
        if (host == "REDACTED") { reason = "HOSTFAKE_HOST_RANGE_NOT_CATALOGUED"; return false; }
        int length = host.Length, start = cut - Math.Max(1, length / 2);
        if (start < 1 || length < 3 || start + length > payload.Length
            || !payload.Slice(start, length).SequenceEqual(Encoding.ASCII.GetBytes(host))) return false;
        return BuildRange(original, tcp, start, length, out steps, out reason);
    }
    public static bool TryBuildStructural(byte[] original, TlsHostRange range, out IReadOnlyList<TcpWireStep> steps, out string reason, bool localhostFixture = false)
    {
        steps = []; reason = "HOSTFAKE_STRUCTURAL_RANGE_INVALID";
        if (!TcpPacket.TryParse(original, out var tcp) || tcp is null || original.Length > TlsClientHelloSplit.MaximumOriginalLength
            || tcp.Flags is not (0x10 or 0x18) || range.Length is < 3 or > 253 || range.Start < 1 || range.Start > tcp.PayloadLength - range.Length
            || !TlsSniEvidence.IsSafe(range.Sni) || !(Allowed(range.Sni) || localhostFixture && range.Sni.HostSha256 == TlsSniEvidence.FromHost("localhost").HostSha256)) return false;
        var name = original.AsSpan(tcp.PayloadOffset + range.Start, range.Length);
        foreach (var b in name) if (!(b is >= 65 and <= 90 or >= 97 and <= 122 or >= 48 and <= 57 or 45 or 46)) return false;
        if (TlsSniEvidence.FromHost(Encoding.ASCII.GetString(name)) != range.Sni) return false;
        return BuildRange(original, tcp, range.Start, range.Length, out steps, out reason);
    }
    private static bool BuildRange(byte[] original, TcpPacket tcp, int start, int length, out IReadOnlyList<TcpWireStep> steps, out string reason)
    {
        steps = []; reason = "HOSTFAKE_UNSUPPORTED_CURRENT_SEGMENT";
        var payload = original.AsSpan(tcp.PayloadOffset);
        if (!TcpTimestampOptions.TryRead(original, tcp, out _, out _, out var echo) || echo == 0)
        { reason = "HOSTFAKE_TCP_TIMESTAMPS_NOT_EVIDENCED"; return false; }

        var prefix = TlsClientHelloSplit.Segment(original, tcp, 0, start, false);
        var fake = TlsClientHelloSplit.Segment(original, tcp, start, length, false);
        // Equal-length, independently generated harmless fake host. No application random/cookies logged or copied into fake data.
        var fakeHost = Enumerable.Repeat((byte)'a', length).ToArray(); var suffix = Encoding.ASCII.GetBytes("mail.ru");
        if (length > suffix.Length) { fakeHost[length - suffix.Length - 1] = (byte)'.'; suffix.CopyTo(fakeHost, length - suffix.Length); }
        fakeHost.CopyTo(fake, tcp.PayloadOffset);
        TcpTimestampOptions.TryRead(fake, tcp, out var ts, out var value, out _);
        BinaryPrimitives.WriteUInt32BigEndian(fake.AsSpan(ts), unchecked(value - TimestampAge));
        FixTcpChecksum(fake, tcp);

        int after = start + length, remaining = payload.Length - after;
        if (remaining > 0)
            steps = [new(prefix, false), new(fake, true), new(TlsClientHelloSplit.Segment(original, tcp, after, remaining, true), false),
                new(TlsClientHelloSplit.Segment(original, tcp, start, length, false), false)];
        else
        {
            // Exactly three real ranges even when SNI is the final extension (observed short updater Hello).
            int half = length / 2;
            steps = [new(prefix, false), new(fake, true), new(TlsClientHelloSplit.Segment(original, tcp, start, half, false), false),
                new(TlsClientHelloSplit.Segment(original, tcp, start + half, length - half, true), false)];
        }
        // Distinct IPv4 IDs, never fragments. Preserve addresses, ACK, real TS and all stream bytes.
        if (!tcp.IsV6)
        {
            var id = BinaryPrimitives.ReadUInt16BigEndian(original.AsSpan(4));
            for (int i = 0; i < steps.Count; i++)
            {
                var bytes = steps[i].Packet; BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), unchecked((ushort)(id + i)));
                bytes[10] = bytes[11] = 0; BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(10), InternetChecksum.Compute(bytes.AsSpan(0, tcp.IpLength)));
            }
        }
        reason = "HOSTFAKE_TS_ALTORDER_STREAM_PRESERVED"; return true;
    }
    private static void FixTcpChecksum(byte[] packet, TcpPacket tcp)
    {
        packet[tcp.IpLength + 16] = packet[tcp.IpLength + 17] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(tcp.IpLength + 16), TlsClientHelloSplit.Checksum(packet, tcp));
    }
}
