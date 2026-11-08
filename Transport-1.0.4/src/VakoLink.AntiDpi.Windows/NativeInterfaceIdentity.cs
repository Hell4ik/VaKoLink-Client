using System.Runtime.InteropServices;
using System.Text.Json.Nodes;

namespace VakoLink.AntiDpi.Windows;

/// <summary>Read-only GetIfEntry2 identity, captured with each private network snapshot. No alias heuristics or persistent index allowlist.</summary>
public static class NativeInterfaceIdentity
{
    // Windows SDK MIB_IF_ROW2, Windows x64: full 1352-byte output buffer, including unused strings/counters.
    // Explicit offsets avoid marshaling strings and never expose the native LUID/physical addresses.
    [StructLayout(LayoutKind.Explicit, Size = 1352)]
    private struct IfRow
    {
        [FieldOffset(8)] public uint Index;
        [FieldOffset(12)] public Guid Guid;
        [FieldOffset(1124)] public uint Mtu;
        [FieldOffset(1128)] public uint Type;
        [FieldOffset(1132)] public uint TunnelType;
        [FieldOffset(1152)] public byte Flags;
        [FieldOffset(1156)] public uint OperStatus;
        [FieldOffset(1160)] public uint AdminStatus;
    }
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetIfEntry2(ref IfRow row);

    public static JsonArray Capture(IEnumerable<int> indexes)
    {
        var result = new JsonArray();
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess) return result;
        foreach (int index in indexes.Where(i => i > 0).Distinct().Take(512))
        {
            var row = new IfRow { Index = (uint)index };
            if (GetIfEntry2(ref row) != 0 || row.Index != index || row.Guid == Guid.Empty
                || row.Type > int.MaxValue || row.TunnelType > int.MaxValue || row.Mtu > int.MaxValue
                || row.OperStatus > int.MaxValue || row.AdminStatus > int.MaxValue) continue;
            result.Add(new JsonObject { ["InterfaceIndex"] = index, ["Guid"] = row.Guid.ToString("D"),
                ["Type"] = checked((int)row.Type), ["TunnelType"] = checked((int)row.TunnelType), ["Hardware"] = (row.Flags & 1) != 0,
                ["Mtu"] = checked((int)row.Mtu), ["OperStatus"] = checked((int)row.OperStatus), ["AdminStatus"] = checked((int)row.AdminStatus) });
        }
        return result;
    }
}
