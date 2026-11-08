using System.Buffers.Binary;

namespace VakoLink.AntiDpi.Core;

public static class FakePacketBuilder
{
    public const int SyntheticPayloadLength = 64;

    /// <summary>
    /// Builds exactly one synthetic datagram; the caller owns repetition and flow-budget enforcement.
    /// Never copies application payload or IPv4 options. Observe returns an empty array.
    /// Checksums are correct except for the explicitly selected bad-UDP-checksum strategy.
    /// A low TTL is an experiment, not a guarantee that packets cannot reach their destination.
    /// </summary>
    public static byte[] Build(byte[] original, StrategyDefinition strategy)
    {
        ArgumentNullException.ThrowIfNull(original);
        StrategyCatalog.Validate(strategy);
        if (strategy.Mode == StrategyMode.Observe)
        {
            return [];
        }
        if (!StrategyCatalog.HasUdp(strategy)) throw new ArgumentException("UDP_STRATEGY_REQUIRED", nameof(strategy));

        if (!Ipv4UdpPacket.TryParse(original, out var parsed) || parsed is null
            || parsed.TotalLength > StrategyCatalog.MaximumPacketSize)
        {
            throw new ArgumentException("Only a bounded, complete IPv4 UDP datagram can be used.", nameof(original));
        }

        const int ipHeaderLength = 20;
        const int udpLength = 8 + SyntheticPayloadLength;
        var fake = new byte[ipHeaderLength + udpLength];
        fake[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(fake.AsSpan(2, 2), (ushort)fake.Length);
        // Preserve only the packet identifier, DF bit, and exact flow tuple; no options or payload.
        original.AsSpan(4, 2).CopyTo(fake.AsSpan(4, 2));
        fake[6] = (byte)(original[6] & 0x40);
        fake[8] = strategy.Ttl;
        fake[9] = 17;
        BinaryPrimitives.WriteUInt32BigEndian(fake.AsSpan(12, 4), parsed.Flow.SourceAddress);
        BinaryPrimitives.WriteUInt32BigEndian(fake.AsSpan(16, 4), parsed.Flow.DestinationAddress);
        BinaryPrimitives.WriteUInt16BigEndian(fake.AsSpan(20, 2), parsed.Flow.SourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(fake.AsSpan(22, 2), parsed.Flow.DestinationPort);
        BinaryPrimitives.WriteUInt16BigEndian(fake.AsSpan(24, 2), udpLength);

        var udpChecksum = InternetChecksum.ComputeUdp(fake);
        if (udpChecksum == 0)
        {
            udpChecksum = ushort.MaxValue; // IPv4 UDP zero denotes checksum disabled.
        }

        if (strategy.Mode == StrategyMode.UdpFakeBadChecksum)
        {
            udpChecksum = udpChecksum == 1 ? (ushort)2 : (ushort)1;
        }

        BinaryPrimitives.WriteUInt16BigEndian(fake.AsSpan(26, 2), udpChecksum);
        BinaryPrimitives.WriteUInt16BigEndian(fake.AsSpan(10, 2), InternetChecksum.Compute(fake.AsSpan(0, 20)));
        return fake;
    }
}
