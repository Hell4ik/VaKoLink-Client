using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace VakoLink.AntiDpi.Windows;

[StructLayout(LayoutKind.Explicit, Size = 80)]
public struct DivertAddress
{
    [FieldOffset(0)] public long Timestamp;
    [FieldOffset(8)] public uint Bits;
    [FieldOffset(12)] public uint Reserved;
    [FieldOffset(16)] public uint InterfaceIndex;
    [FieldOffset(20)] public uint SubInterfaceIndex;
    [FieldOffset(16)] public ulong Endpoint;
    [FieldOffset(24)] public ulong ParentEndpoint;
    [FieldOffset(32)] public uint ProcessId;
    [FieldOffset(36)] public uint Local0;
    [FieldOffset(40)] public uint Local1;
    [FieldOffset(44)] public uint Local2;
    [FieldOffset(48)] public uint Local3;
    [FieldOffset(52)] public uint Remote0;
    [FieldOffset(56)] public uint Remote1;
    [FieldOffset(60)] public uint Remote2;
    [FieldOffset(64)] public uint Remote3;
    [FieldOffset(68)] public ushort LocalPort;
    [FieldOffset(70)] public ushort RemotePort;
    [FieldOffset(72)] public byte Protocol;

    public readonly int Event => (int)((Bits >> 8) & 255);
    public readonly bool Outbound => (Bits & (1u << 17)) != 0;
    public readonly bool IPv6 => (Bits & (1u << 20)) != 0;
    public readonly bool Impostor => (Bits & (1u << 19)) != 0;
}

internal static class NativeMethods
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr LoadLibraryEx(string path, IntPtr reserved, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool FreeLibrary(IntPtr module);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    internal static extern IntPtr GetProcAddress(IntPtr module, string name);
    [DllImport("iphlpapi.dll")]
    internal static extern uint GetExtendedUdpTable(IntPtr table, ref uint size,
        [MarshalAs(UnmanagedType.Bool)] bool order, uint family, int tableClass, uint reserved);
    [DllImport("iphlpapi.dll")]
    internal static extern uint GetExtendedTcpTable(IntPtr table, ref uint size,
        [MarshalAs(UnmanagedType.Bool)] bool order, uint family, int tableClass, uint reserved);
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags,
        System.Text.StringBuilder buffer, ref uint length);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetProcessTimes(SafeProcessHandle process,
        out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);
    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool QueryPerformanceCounter(out long counter);
    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool QueryPerformanceFrequency(out long frequency);
    [DllImport("kernel32.dll")]
    internal static extern void GetSystemTimePreciseAsFileTime(out long fileTime);
}

internal sealed class WinDivertLibrary : IDisposable
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi, SetLastError = true)]
    internal delegate IntPtr OpenDelegate(string filter, int layer, short priority, ulong flags);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal delegate bool RecvDelegate(IntPtr handle, [Out] byte[]? packet, uint length, out uint received, out DivertAddress address);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal delegate bool SendDelegate(IntPtr handle, byte[] packet, uint length, out uint sent, ref DivertAddress address);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal delegate bool CompileDelegate(string filter, int layer,
        IntPtr compiledObject, uint objectLength, out IntPtr error, out uint position);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal delegate bool EvalDelegate(string filter, byte[] packet, uint length, ref DivertAddress address);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] internal delegate bool ShutdownDelegate(IntPtr handle, int how);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] internal delegate bool CloseDelegate(IntPtr handle);
    private IntPtr _module;
    internal OpenDelegate Open { get; }
    internal RecvDelegate Recv { get; }
    internal SendDelegate Send { get; }
    internal ShutdownDelegate Shutdown { get; }
    internal CloseDelegate Close { get; }
    internal CompileDelegate Compile { get; }
    internal EvalDelegate Eval { get; }

    internal WinDivertLibrary(string absoluteDll)
    {
        _module = NativeMethods.LoadLibraryEx(absoluteDll, IntPtr.Zero, 0x100 | 0x800);
        if (_module == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            Open = Export<OpenDelegate>("WinDivertOpen");
            Recv = Export<RecvDelegate>("WinDivertRecv");
            Send = Export<SendDelegate>("WinDivertSend");
            Shutdown = Export<ShutdownDelegate>("WinDivertShutdown");
            Close = Export<CloseDelegate>("WinDivertClose");
            Compile = Export<CompileDelegate>("WinDivertHelperCompileFilter");
            Eval = Export<EvalDelegate>("WinDivertHelperEvalFilter");
        }
        catch { Dispose(); throw; }
    }
    private T Export<T>(string name) where T : Delegate
    {
        var export = NativeMethods.GetProcAddress(_module, name);
        if (export == IntPtr.Zero) throw new EntryPointNotFoundException(name);
        return Marshal.GetDelegateForFunctionPointer<T>(export);
    }
    public void Dispose()
    {
        if (_module != IntPtr.Zero)
        {
            if (!NativeMethods.FreeLibrary(_module)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            _module = IntPtr.Zero;
        }
    }
}

// Internal seam for lifecycle tests. Public entry points always use the real, verified package.
internal interface IDivertApi : IDisposable
{
    IntPtr Open(string filter, int layer, short priority, ulong flags);
    bool Recv(IntPtr handle, byte[]? packet, uint length, out uint received, out DivertAddress address);
    bool Send(IntPtr handle, byte[] packet, uint length, out uint sent, ref DivertAddress address);
    bool Shutdown(IntPtr handle, int how);
    bool Close(IntPtr handle);
}

internal sealed class NativeDivertApi : IDivertApi
{
    private readonly WinDivertLibrary _library;
    internal NativeDivertApi(string absoluteDll) => _library = new WinDivertLibrary(absoluteDll);
    public IntPtr Open(string filter, int layer, short priority, ulong flags) => _library.Open(filter, layer, priority, flags);
    public bool Recv(IntPtr handle, byte[]? packet, uint length, out uint received, out DivertAddress address) =>
        _library.Recv(handle, packet, length, out received, out address);
    public bool Send(IntPtr handle, byte[] packet, uint length, out uint sent, ref DivertAddress address) =>
        _library.Send(handle, packet, length, out sent, ref address);
    public bool Shutdown(IntPtr handle, int how) => _library.Shutdown(handle, how);
    public bool Close(IntPtr handle) => _library.Close(handle);
    public void Dispose() => _library.Dispose();
}
