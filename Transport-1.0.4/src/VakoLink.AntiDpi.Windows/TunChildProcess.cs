using System.Diagnostics;
using System.Runtime.InteropServices;

namespace VakoLink.AntiDpi.Windows;

// Own hidden console + suspended creation/job assignment: never signals an unrelated/shared console.
internal sealed class TunChildProcess : IDisposable
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct Startup { public uint cb; public string? reserved, desktop, title; public uint x, y, w, h, charsX, charsY, fill, flags; public ushort show, reserved2; public IntPtr pReserved, input, output, error; }
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInfo { public IntPtr process, thread; public uint pid, tid; }
    [StructLayout(LayoutKind.Sequential)] private struct Limits { public long processTime, jobTime; public uint flags; public UIntPtr min, max; public uint active; public UIntPtr affinity; public uint priority, scheduling; }
    [StructLayout(LayoutKind.Sequential)] private struct Extended { public Limits limits; public ulong readOps, writeOps, otherOps, readBytes, writeBytes, otherBytes; public UIntPtr processMemory, jobMemory, peakProcessMemory, peakJobMemory; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool CreateProcessW(string app, System.Text.StringBuilder command, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr environment, string directory, ref Startup startup, out ProcessInfo info);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr CreateJobObjectW(IntPtr a, string? name);
    [DllImport("kernel32.dll")] private static extern bool SetInformationJobObject(IntPtr job, int cls, ref Extended limits, uint length);
    [DllImport("kernel32.dll")] private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll")] private static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")] private static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] private static extern bool AttachConsole(uint pid);
    [DllImport("kernel32.dll")] private static extern bool FreeConsole();
    [DllImport("kernel32.dll")] private static extern bool SetConsoleCtrlHandler(IntPtr handler, bool add);
    [DllImport("kernel32.dll")] private static extern bool GenerateConsoleCtrlEvent(uint ctrl, uint group);
    [DllImport("kernel32.dll")] private static extern uint GetConsoleProcessList([Out] uint[] ids, uint length);
    [StructLayout(LayoutKind.Sequential)] private struct Security { public int length; public IntPtr descriptor; [MarshalAs(UnmanagedType.Bool)] public bool inherit; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateFileW(string path, uint access, uint share, ref Security security, uint creation, uint flags, IntPtr template);
    private IntPtr _job; public Process Process { get; private set; } = null!; public bool GracefulSignal, Forced;
    public void Start(string config)
    {
        _job = CreateJobObjectW(IntPtr.Zero, null); var limits = new Extended { limits = new Limits { flags = 0x2000 } };
        if (_job == IntPtr.Zero || !SetInformationJobObject(_job, 9, ref limits, (uint)Marshal.SizeOf<Extended>())) throw new IOException("TUN_JOB_FAILED");
        // Only fatal command stderr/stdout: normal core logging remains disabled. Private ACL directory, later DPAPI + deletion.
        var security = new Security { length = Marshal.SizeOf<Security>(), inherit = true };
        IntPtr error = CreateFileW(Path.Combine(Path.GetDirectoryName(config)!, "core-stderr.txt"), 0x40000000, 1, ref security, 1, 0x80, IntPtr.Zero);
        IntPtr input = CreateFileW("NUL", 0x80000000, 3, ref security, 3, 0x80, IntPtr.Zero);
        ProcessInfo p;
        try
        {
            if (error == new IntPtr(-1) || input == new IntPtr(-1)) throw new IOException("TUN_STDERR_CAPTURE_FAILED");
            var start = new Startup { cb = (uint)Marshal.SizeOf<Startup>(), flags = 0x101, show = 0, input = input, output = error, error = error };
            var command = new System.Text.StringBuilder('"' + AionTunPlan.CorePath + "\" run -c \"" + config + '"');
            if (!CreateProcessW(AionTunPlan.CorePath, command, IntPtr.Zero, IntPtr.Zero, true, 0x10 | 4, IntPtr.Zero, Path.GetDirectoryName(config)!, ref start, out p)) throw new IOException("TUN_CORE_START_FAILED");
        }
        finally { if (error != new IntPtr(-1)) CloseHandle(error); if (input != new IntPtr(-1)) CloseHandle(input); }
        try
        {
            if (!AssignProcessToJobObject(_job, p.process)) { TerminateProcess(p.process, 2); throw new IOException("TUN_JOB_ASSIGN_FAILED"); }
            Process = Process.GetProcessById((int)p.pid); if (ResumeThread(p.thread) == uint.MaxValue) { TerminateProcess(p.process, 2); throw new IOException("TUN_CORE_RESUME_FAILED"); }
        }
        finally { CloseHandle(p.thread); CloseHandle(p.process); }
    }
    public async Task StopAsync()
    {
        if (Process is null || Process.HasExited) return;
        bool attached = AttachConsole((uint)Process.Id);
        try
        {
            if (attached)
            {
                var ids = new uint[8]; uint count = GetConsoleProcessList(ids, 8);
                if (count > 0 && count <= 8 && ids.Take((int)count).All(id => id == (uint)Process.Id || id == (uint)Environment.ProcessId))
                { SetConsoleCtrlHandler(IntPtr.Zero, true); GracefulSignal = GenerateConsoleCtrlEvent(0, 0); }
            }
            // CTRL_C is delivered asynchronously. Retain ignore + attachment until the child has exited;
            // detaching/resetting immediately can expose the GUI parent to its still-pending CTRL_C event.
            try { await Process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(12)); }
            catch (TimeoutException) { Forced = true; Process.Kill(); await Process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); }
        }
        finally { if (attached) { FreeConsole(); SetConsoleCtrlHandler(IntPtr.Zero, false); } }
    }
    public void Dispose() { if (_job != IntPtr.Zero) { CloseHandle(_job); _job = IntPtr.Zero; } Process?.Dispose(); }
}
