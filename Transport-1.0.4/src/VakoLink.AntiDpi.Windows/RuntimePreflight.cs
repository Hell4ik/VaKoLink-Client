using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;

namespace VakoLink.AntiDpi.Windows;

public static class RuntimePreflight
{
    // Pinned to the inspected local package, NOT evidence that it is an upstream release asset.
    public const string DllSha256 = "C1E060EE19444A259B2162F8AF0F3FE8C4428A1C6F694DCE20DE194AC8D7D9A2";
    public const string DriverSha256 = "8DA085332782708D8767BCACE5327A6EC7283C17CFB85E40B03CD2323A90DDC2";
    public static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static Task<string> InspectAsync(string engineDirectory, CancellationToken token = default) => Task.Run(() =>
    {
        VerifyPackage(engineDirectory, token);
        using (var library = new WinDivertLibrary(Path.Combine(engineDirectory, "WinDivert.dll")))
        {
            foreach (var (filter, layer) in new[] { ("udp and !ipv6", 2), ("udp and !ipv6", 3),
                ("outbound and ip and udp and !loopback and !impostor", 0),
                ("inbound and ip and udp and !loopback and !impostor", 0), ("false", 0),
                ("tcp or (udp and !ipv6)", 2), ("tcp or (udp and !ipv6)", 3),
                ("tcp and !loopback and !impostor", 0),
                ("tcp and !loopback and !impostor and outbound and tcp.PayloadLength > 0 and (tcp.DstPort == 443 or tcp.DstPort == 2053 or tcp.DstPort == 2083 or tcp.DstPort == 2087 or tcp.DstPort == 2096 or tcp.DstPort == 8443)", 0) })
                if (!library.Compile(filter, layer, IntPtr.Zero, 0, out _, out var position))
                    throw new InvalidOperationException($"FILTER_COMPILATION_FAILED:L{layer}:P{position}");
        }
        var conflicts = GetConflicts();
        return $"WinDivert: SHA-256/AMD64/Authenticode/filters OK; admin={IsAdministrator()}; conflicts={conflicts.Count}. TCP/TLS split is an unverified candidate; IPv6 TCP base headers supported, IPv6 UDP unchanged.";
    }, token);

    internal static void VerifyPackage(string directory, CancellationToken token)
    {
        if (!Environment.Is64BitProcess || !Path.IsPathFullyQualified(directory))
            throw new InvalidOperationException("ENGINE_PATH_OR_ARCHITECTURE");
        var dll = Path.Combine(directory, "WinDivert.dll");
        var driver = Path.Combine(directory, "WinDivert64.sys");
        VerifyFile(dll, DllSha256);
        VerifyFile(driver, DriverSha256);
        token.ThrowIfCancellationRequested();
        if (!AuthenticodeVerifier.IsTrusted(driver)) throw new InvalidOperationException("DRIVER_SIGNATURE_NOT_TRUSTED");
    }
    internal static void VerifyFile(string path, string expected)
    {
        var file = new FileInfo(path);
        if (!file.Exists || file.Length is < 64 or > 4_000_000 || (file.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("ENGINE_FILE_INVALID");
        var bytes = File.ReadAllBytes(path);
        if (!string.Equals(Convert.ToHexString(SHA256.HashData(bytes)), expected, StringComparison.Ordinal))
            throw new InvalidOperationException("ENGINE_HASH_MISMATCH");
        if (!IsAmd64Pe(bytes)) throw new InvalidOperationException("ENGINE_ARCHITECTURE_MISMATCH");
    }
    public static bool IsAmd64Pe(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 64 || bytes[0] != 'M' || bytes[1] != 'Z') return false;
        var offset = BinaryPrimitives.ReadInt32LittleEndian(bytes[60..]);
        return offset >= 64 && offset <= bytes.Length - 24
            && BinaryPrimitives.ReadUInt32LittleEndian(bytes[offset..]) == 0x00004550
            && BinaryPrimitives.ReadUInt16LittleEndian(bytes[(offset + 4)..]) == 0x8664;
    }
    public static IReadOnlyList<string> GetConflicts()
    {
        var conflicts = new List<string>();
        foreach (var name in new[] { "winws", "winws2", "goodbyedpi" })
        {
            foreach (var process in Process.GetProcessesByName(name))
            {
                using (process) conflicts.Add(name);
            }
        }
        return conflicts;
    }
}
