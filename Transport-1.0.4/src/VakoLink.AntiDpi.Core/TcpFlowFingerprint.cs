using System.Buffers.Binary;
using System.Security.Cryptography;

namespace VakoLink.AntiDpi.Core;

public static class TcpFlowFingerprint
{
    public static byte[] AddressBytes(PacketAddress address)
    {
        var bytes = new byte[address.V6 ? 16 : 4]; BinaryPrimitives.WriteUInt32BigEndian(bytes, address.A);
        if (address.V6) { BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(4), address.B); BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(8), address.C); BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(12), address.D); }
        return bytes;
    }
    // Fingerprints support before/after joining without raw addresses. Hashes are NOT a promise of anonymization.
    public static string RemoteAddress(TcpFlow flow) => Convert.ToHexString(SHA256.HashData(AddressBytes(flow.Remote)));
    public static string Flow(TcpFlow flow)
    {
        var local = AddressBytes(flow.Local); var remote = AddressBytes(flow.Remote); var bytes = new byte[local.Length + remote.Length + 4];
        local.CopyTo(bytes, 0); remote.CopyTo(bytes, local.Length);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(bytes.Length - 4), flow.LocalPort); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(bytes.Length - 2), flow.RemotePort);
        return Convert.ToHexString(SHA256.HashData(bytes));
    }
}
