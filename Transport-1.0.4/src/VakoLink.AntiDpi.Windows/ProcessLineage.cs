using System.Runtime.InteropServices;

namespace VakoLink.AntiDpi.Windows;

internal static class ProcessLineage
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Entry
    {
        public uint Size, Usage, ProcessId;
        public UIntPtr Heap;
        public uint ModuleId, Threads, ParentProcessId;
        public int Priority;
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Name;
    }
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint process);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool Process32FirstW(IntPtr snapshot, ref Entry entry);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool Process32NextW(IntPtr snapshot, ref Entry entry);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    // Outside packet workers. Parent observation NEVER authorizes a child image for interception.
    internal static IReadOnlyDictionary<uint, uint> Capture()
    {
        var result = new Dictionary<uint, uint>(); var snapshot = CreateToolhelp32Snapshot(2, 0);
        if (snapshot == new IntPtr(-1)) return result;
        try
        {
            var entry = new Entry { Size = (uint)Marshal.SizeOf<Entry>(), Name = string.Empty };
            if (!Process32FirstW(snapshot, ref entry)) return result;
            do { result[entry.ProcessId] = entry.ParentProcessId; } while (result.Count < 8192 && Process32NextW(snapshot, ref entry));
        }
        finally { CloseHandle(snapshot); }
        return result;
    }
}
