using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace VakoLink.AntiDpi.Windows;

// A PRIVATE ConPTY, not AttachConsole/console-wide events or global input injection.
// Terminal output is drained in fixed buffers and discarded; never exported/logged.
// A kill-on-close job owns only this created process and any descendants, including
// on host crash. No service, registry, network settings or external process control.
internal sealed class OwnedConsoleProcess
{
    private IntPtr _console, _input, _output, _job;
    private Task? _drain, _consoleClose;
    private Action<byte[], int>? _outputSink;
    internal Process Process { get; private set; } = null!;

    internal static OwnedConsoleProcess Start(string executable, IReadOnlyList<string> arguments, string directory, Action<byte[], int>? readOnlyProbeOutput = null)
    {
        if (!Environment.Is64BitProcess || !OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763))
            throw new InvalidOperationException("REFERENCE_CONPTY_UNAVAILABLE");
        var command = CommandLine(executable, arguments);
        if (readOnlyProbeOutput is not null && arguments[0] is not ("--version" or "--help" or "--dry-run"))
            throw new ArgumentException("OUTPUT_CAPTURE_ONLY_READONLY_PROBE");
        var owned = new OwnedConsoleProcess { _outputSink = readOnlyProbeOutput };
        IntPtr readInput = IntPtr.Zero, writeOutput = IntPtr.Zero, attributes = IntPtr.Zero;
        bool initialized = false;
        ProcessInformation information = default;
        try
        {
            Check(CreatePipe(out readInput, out owned._input, IntPtr.Zero, 0));
            Check(CreatePipe(out owned._output, out writeOutput, IntPtr.Zero, 0));
            var status = CreatePseudoConsole(new Coord { X = 120, Y = 30 }, readInput, writeOutput, 0, out owned._console);
            if (status < 0) Marshal.ThrowExceptionForHR(status);
            owned._drain = Task.Factory.StartNew(owned.DiscardOutput, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
            nuint bytes = 0;
            _ = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref bytes);
            if (bytes is 0 or > 65536) throw new InvalidOperationException("REFERENCE_ATTRIBUTE_SIZE");
            attributes = Marshal.AllocHGlobal((int)bytes);
            Check(InitializeProcThreadAttributeList(attributes, 1, 0, ref bytes)); initialized = true;
            Check(UpdateProcThreadAttribute(attributes, 0, (nuint)0x00020016, owned._console, (nuint)IntPtr.Size, IntPtr.Zero, IntPtr.Zero));
            var startup = new StartupInfoEx { Attributes = attributes };
            startup.Info.Size = (uint)Marshal.SizeOf<StartupInfoEx>();
            owned._job = CreateJobObjectW(IntPtr.Zero, null); Check(owned._job != IntPtr.Zero);
            // AMD64 JOBOBJECT_EXTENDED_LIMIT_INFORMATION: 144 bytes, LimitFlags at16.
            var limit = Marshal.AllocHGlobal(144);
            try
            {
                Marshal.Copy(new byte[144], 0, limit, 144);
                Marshal.WriteInt32(limit, 16, 0x2000); // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                Check(SetInformationJobObject(owned._job, 9, limit, 144));
            }
            finally { Marshal.FreeHGlobal(limit); }
            Check(CreateProcessW(executable, new StringBuilder(command), IntPtr.Zero, IntPtr.Zero, false,
                0x00080004, IntPtr.Zero, directory, ref startup, out information)); // extended + suspended
            Check(AssignProcessToJobObject(owned._job, information.Process));
            owned.Process = Process.GetProcessById((int)information.Id);
            _ = owned.Process.SafeHandle; // Cache the handle while our created child is still suspended.
            if (ResumeThread(information.Thread) == uint.MaxValue) throw new Win32Exception(Marshal.GetLastWin32Error());
            return owned;
        }
        catch
        {
            // Only a native handle returned by OUR CreateProcess, never lookup/kill by name.
            if (information.Process != IntPtr.Zero)
            {
                _ = TerminateProcess(information.Process, 1);
                _ = WaitForSingleObject(information.Process, 3000);
            }
            Close(ref owned._job);
            Close(ref readInput); Close(ref writeOutput);
            owned.CloseTerminalAsync().GetAwaiter().GetResult();
            owned.Process?.Dispose();
            throw;
        }
        finally
        {
            if (initialized) DeleteProcThreadAttributeList(attributes);
            if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
            Close(ref readInput); Close(ref writeOutput);
            Close(ref information.Thread); Close(ref information.Process);
        }
    }

    internal bool SendInterrupt() => _input != IntPtr.Zero && WriteFile(_input, [3], 1, out var written, IntPtr.Zero) && written == 1;

    internal async Task DisposeAfterExitAsync()
    {
        if (!Process.HasExited) throw new InvalidOperationException("REFERENCE_PROCESS_RETAINED");
        await CloseTerminalAsync(); Close(ref _job);
    }

    private async Task CloseTerminalAsync()
    {
        Close(ref _input);
        if (_console != IntPtr.Zero)
        {
            var console = _console;
            _consoleClose ??= Task.Factory.StartNew(() => ClosePseudoConsole(console), CancellationToken.None,
                TaskCreationOptions.LongRunning, TaskScheduler.Default);
            await _consoleClose.WaitAsync(TimeSpan.FromSeconds(3));
            _console = IntPtr.Zero;
        }
        if (_drain is not null) { await _drain.WaitAsync(TimeSpan.FromSeconds(3)); _drain = null; }
        Close(ref _output);
    }
    private void DiscardOutput()
    {
        var buffer = new byte[4096];
        while (ReadFile(_output, buffer, (uint)buffer.Length, out var read, IntPtr.Zero) && read != 0)
        {
            _outputSink?.Invoke(buffer, checked((int)read));
            Array.Clear(buffer); // Active engine output is still always discarded, never logged.
        }
    }
    private static void Check(bool okay) { if (!okay) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    private static void Close(ref IntPtr handle)
    { if (handle == IntPtr.Zero) return; Check(CloseHandle(handle)); handle = IntPtr.Zero; }

    internal static string CommandLine(string executable, IReadOnlyList<string> arguments)
    {
        if (!Path.IsPathFullyQualified(executable) || arguments.Count > 200) throw new ArgumentException("REFERENCE_COMMAND_INVALID");
        var text = string.Join(" ", new[] { executable }.Concat(arguments).Select(Quote));
        if (text.Length >= 32767) throw new ArgumentException("REFERENCE_COMMAND_LIMIT");
        return text;
    }
    internal static string Quote(string value)
    {
        if (value.IndexOfAny(['\0', '\r', '\n']) >= 0) throw new ArgumentException("REFERENCE_ARGUMENT_INVALID");
        var result = new StringBuilder("\""); int slashes = 0;
        foreach (var character in value)
        {
            if (character == '\\') { slashes++; continue; }
            if (character == '"') { result.Append('\\', slashes * 2 + 1).Append('"'); slashes = 0; continue; }
            result.Append('\\', slashes).Append(character); slashes = 0;
        }
        return result.Append('\\', slashes * 2).Append('"').ToString();
    }

    [StructLayout(LayoutKind.Sequential)] private struct Coord { internal short X, Y; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        internal uint Size;
        internal IntPtr Reserved, Desktop, Title;
        internal uint X, Y, Width, Height, CharWidth, CharHeight, Fill, Flags;
        internal ushort ShowWindow, ReservedSize;
        internal IntPtr ReservedBytes, Input, Output, Error;
    }
    [StructLayout(LayoutKind.Sequential)] private struct StartupInfoEx { internal StartupInfo Info; internal IntPtr Attributes; }
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInformation { internal IntPtr Process, Thread; internal uint Id, ThreadId; }
    [DllImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static extern bool CreatePipe(out IntPtr read, out IntPtr write, IntPtr attributes, uint size);
    [DllImport("kernel32.dll")] private static extern int CreatePseudoConsole(Coord size, IntPtr input, IntPtr output, uint flags, out IntPtr console);
    [DllImport("kernel32.dll")] private static extern void ClosePseudoConsole(IntPtr console);
    [DllImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, uint flags, ref nuint bytes);
    [DllImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, nuint attribute, IntPtr value, nuint size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)][return: MarshalAs(UnmanagedType.Bool)] private static extern bool CreateProcessW(string application, StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string directory, ref StartupInfoEx startup, out ProcessInformation information);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern IntPtr CreateJobObjectW(IntPtr attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetInformationJobObject(IntPtr job, int kind, IntPtr information, uint bytes);
    [DllImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static extern bool ReadFile(IntPtr handle, byte[] buffer, uint bytes, out uint read, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static extern bool WriteFile(IntPtr handle, byte[] buffer, uint bytes, out uint written, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr handle);
}
