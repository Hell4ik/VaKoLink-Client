using System.Runtime.InteropServices;

namespace VakoLink.AntiDpi.Windows;

public sealed record PacketMonitorCapabilityEvidence(bool DllAvailable, bool AllRequiredExports,
    IReadOnlyDictionary<string, bool> Exports, bool DllUnloaded, bool CaptureStarted = false,
    bool SessionCreated = false, int NetworkConfigurationMutations = 0,
    string Scope = "Read-only public API export inventory of System32 PktMonApi.dll. No initialize/session/filter/capture calls, no CLI configuration changes. Export presence alone is not capture readiness.");

public static class PacketMonitorCapabilityProbe
{
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate int Initialize(uint version, IntPtr reserved, out IntPtr handle);
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)] private delegate int CreateSession(IntPtr handle, string name, out IntPtr session);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate void CloseHandle(IntPtr handle);

    public static PacketMonitorApiLifecycleEvidence VerifyInactiveSession()
    {
        if (!RuntimePreflight.IsAdministrator()) throw new InvalidOperationException("ADMIN_REQUIRED");
        IntPtr module = NativeMethods.LoadLibraryEx(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "PktMonApi.dll"), IntPtr.Zero, 0x800);
        if (module == IntPtr.Zero) throw new InvalidOperationException("PKTMON_API_DLL_UNAVAILABLE");
        IntPtr handle = IntPtr.Zero, session = IntPtr.Zero; int? initResult = null, createResult = null;
        bool closed = false, uninitialized = false, unloaded;
        try
        {
            var init = Marshal.GetDelegateForFunctionPointer<Initialize>(NativeMethods.GetProcAddress(module, "PacketMonitorInitialize"));
            var create = Marshal.GetDelegateForFunctionPointer<CreateSession>(NativeMethods.GetProcAddress(module, "PacketMonitorCreateLiveSession"));
            var closeSession = Marshal.GetDelegateForFunctionPointer<CloseHandle>(NativeMethods.GetProcAddress(module, "PacketMonitorCloseSessionHandle"));
            var uninit = Marshal.GetDelegateForFunctionPointer<CloseHandle>(NativeMethods.GetProcAddress(module, "PacketMonitorUninitialize"));
            try
            {
                initResult = init(0x00010000, IntPtr.Zero, out handle);
                if (initResult >= 0 && handle != IntPtr.Zero) createResult = create(handle, "VakoLink-C3-inactive-" + Guid.NewGuid().ToString("N"), out session);
            }
            finally
            {
                if (session != IntPtr.Zero) { closeSession(session); session = IntPtr.Zero; closed = true; }
                if (handle != IntPtr.Zero) { uninit(handle); handle = IntPtr.Zero; uninitialized = true; }
            }
        }
        finally { unloaded = NativeMethods.FreeLibrary(module); }
        return new(initResult is null ? null : $"0x{initResult.Value:X8}", createResult is null ? null : $"0x{createResult.Value:X8}",
            initResult >= 0 && createResult >= 0 && closed && uninitialized && unloaded, closed, uninitialized, unloaded);
    }
    public static PacketMonitorCapabilityEvidence Run()
    {
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "PktMonApi.dll");
        if (!File.Exists(path)) return new(false, false, new Dictionary<string, bool>(), true);
        // System32 only; do not search a package/current directory for an OS DLL.
        IntPtr module = NativeMethods.LoadLibraryEx(path, IntPtr.Zero, 0x800);
        if (module == IntPtr.Zero) return new(true, false, new Dictionary<string, bool>(), true);
        var exports = new Dictionary<string, bool>();
        try
        {
            foreach (string name in new[] { "PacketMonitorInitialize", "PacketMonitorUninitialize", "PacketMonitorCreateLiveSession",
                "PacketMonitorCloseSessionHandle", "PacketMonitorCreateRealtimeStream", "PacketMonitorCloseRealtimeStream",
                "PacketMonitorAddCaptureConstraint", "PacketMonitorAttachOutputToSession", "PacketMonitorSetSessionActive" })
                exports[name] = NativeMethods.GetProcAddress(module, name) != IntPtr.Zero;
        }
        finally
        {
            if (!NativeMethods.FreeLibrary(module)) throw new InvalidOperationException("PKTMON_CAPABILITY_UNLOAD_FAILED");
        }
        return new(true, exports.Values.All(x => x), exports, true);
    }
}

public sealed record PacketMonitorApiLifecycleEvidence(string? InitializeHresult, string? CreateSessionHresult,
    bool InactiveSessionLifecyclePassed, bool SessionClosed, bool Uninitialized, bool DllUnloaded,
    bool SessionActivated = false, bool StreamCreated = false, bool CaptureStarted = false, int SharedCliFilterChanges = 0,
    string Scope = "Own independent inactive Packet Monitor session only. No data sources, constraints, stream or activation, no capture, no ETL files, no CLI filters or network configuration changes. Close/uninitialize APIs return void; returned calls recorded, no claim of capture readiness.");
