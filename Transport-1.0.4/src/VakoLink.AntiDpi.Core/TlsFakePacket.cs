using System.Buffers.Binary;
using System.Text;

namespace VakoLink.AntiDpi.Core;

public static class TlsFakePacket
{
    // Half the 32-bit sequence space, beyond even maximum RFC 7323 scaled TCP receive window.
    // No any-protocol mode: only a positively parsed selected-app ClientHello, max 2 per endpoint.
    public const uint SequenceOffset = 0x80000000;
    public static byte[] Build(byte[] original)
    {
        if (!TcpPacket.TryParse(original, out var tcp) || tcp is null || tcp.Flags is not (0x10 or 0x18)
            || original.Length > TlsClientHelloSplit.MaximumOriginalLength) throw new ArgumentException("TLS_FAKE_CONTRACT");
        // Independently authored small synthetic TLS 1.2 ClientHello. No original cookies, random, SNI or payload copied.
        var host = Encoding.ASCII.GetBytes("www.google.com");
        var hello = new byte[61 + host.Length];
        hello[0] = 22; hello[1] = 3; hello[2] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(hello.AsSpan(3), (ushort)(hello.Length - 5));
        hello[5] = 1; hello[8] = (byte)(hello.Length - 9); hello[9] = 3; hello[10] = 3;
        hello[45] = 2; hello[46] = 0xC0; hello[47] = 0x2F; hello[48] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(hello.AsSpan(50), (ushort)(hello.Length - 52));
        BinaryPrimitives.WriteUInt16BigEndian(hello.AsSpan(54), (ushort)(host.Length + 5));
        BinaryPrimitives.WriteUInt16BigEndian(hello.AsSpan(56), (ushort)(host.Length + 3));
        BinaryPrimitives.WriteUInt16BigEndian(hello.AsSpan(59), (ushort)host.Length); host.CopyTo(hello, 61);
        var result = new byte[tcp.PayloadOffset + hello.Length]; original.AsSpan(0, tcp.PayloadOffset).CopyTo(result);
        hello.CopyTo(result, tcp.PayloadOffset);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(tcp.IpLength + 4), unchecked(tcp.Sequence + SequenceOffset));
        result[tcp.IpLength + 13] = 0x18;
        if (tcp.IsV6) BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), (ushort)(result.Length - 40));
        else
        {
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2), (ushort)result.Length);
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), unchecked((ushort)(BinaryPrimitives.ReadUInt16BigEndian(original.AsSpan(4)) + 1)));
            result[10] = result[11] = 0;
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(10), InternetChecksum.Compute(result.AsSpan(0, tcp.IpLength)));
        }
        result[tcp.IpLength + 16] = result[tcp.IpLength + 17] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(tcp.IpLength + 16), TlsClientHelloSplit.Checksum(result, tcp));
        return result;
    }
}
