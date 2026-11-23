using System.Runtime.InteropServices;

// The dynamic WFP session owns the filters, including when this process crashes.
internal sealed class ApplicationIpv6Guard : IDisposable
{
    private IntPtr _engine;
    private static readonly Guid ConnectV6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    private static readonly Guid ApplicationId = new("d78e1e87-8644-4ea5-9437-d809ecefc971");
    private static readonly Guid UniversalSublayer = new("eebecc03-ced4-4380-819a-2734397b2b74");
    private const uint DynamicSession = 1;
    private const uint MatchEqual = 0;
    private const uint ByteBlob = 12;
    private const uint HardAction = 8;
    private const uint Block = 0x1001;
    private const uint RpcAuthnWinnt = 10;

    internal ApplicationIpv6Guard(IEnumerable<string> applications)
    {
        string[] paths = applications.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (paths.Length == 0) throw new IOException("TUN_IPV6_GUARD_NO_APPS");
        var name = Marshal.StringToHGlobalUni("VaKoLink application routing IPv6 guard");
        try
        {
            var session = new Session { Key = Guid.NewGuid(), Flags = DynamicSession, Display = new() { Name = name } };
            Check(FwpmEngineOpen0(IntPtr.Zero, RpcAuthnWinnt, IntPtr.Zero, ref session, out _engine));
            foreach (string path in paths) BlockApplication(path, name);
        }
        catch
        {
            Dispose();
            throw;
        }
        finally { Marshal.FreeHGlobal(name); }
    }

    private void BlockApplication(string path, IntPtr name)
    {
        IntPtr application = IntPtr.Zero;
        IntPtr condition = IntPtr.Zero;
        try
        {
            Check(FwpmGetAppIdFromFileName0(path, out application));
            condition = Marshal.AllocHGlobal(Marshal.SizeOf<Condition>());
            Marshal.StructureToPtr(new Condition { Field = ApplicationId, Match = MatchEqual,
                Value = new() { Type = ByteBlob, Pointer = application } }, condition, false);
            var filter = new Filter { Key = Guid.NewGuid(), Display = new() { Name = name }, Flags = HardAction,
                Layer = ConnectV6, Sublayer = UniversalSublayer, ConditionCount = 1, Conditions = condition,
                Action = new() { Type = Block } };
            Check(FwpmFilterAdd0(_engine, ref filter, IntPtr.Zero, out _));
        }
        finally
        {
            if (application != IntPtr.Zero) FwpmFreeMemory0(ref application);
            Marshal.FreeHGlobal(condition);
        }
    }

    public void Dispose()
    {
        if (_engine == IntPtr.Zero) return;
        Check(FwpmEngineClose0(_engine));
        _engine = IntPtr.Zero;
    }

    private static void Check(uint result)
    {
        if (result != 0) throw new IOException($"TUN_IPV6_GUARD_0X{result:X8}");
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Display { public IntPtr Name, Description; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Session
    {
        public Guid Key;
        public Display Display;
        public uint Flags, TransactionTimeout, ProcessId;
        public IntPtr Sid, Username;
        public int KernelMode;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct Blob { public uint Size; public IntPtr Data; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Value { public uint Type; public IntPtr Pointer; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Condition { public Guid Field; public uint Match; public Value Value; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Action { public uint Type; public Guid Key; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Filter
    {
        public Guid Key;
        public Display Display;
        public uint Flags;
        public IntPtr Provider;
        public Blob ProviderData;
        public Guid Layer, Sublayer;
        public Value Weight;
        public uint ConditionCount;
        public IntPtr Conditions;
        public Action Action;
        // The native context union is 16 bytes with 8-byte alignment.
        public ulong ContextLow, ContextHigh;
        public IntPtr Reserved;
        public ulong Id;
        public Value EffectiveWeight;
    }

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    private static extern uint FwpmEngineOpen0(IntPtr server, uint authentication, IntPtr authIdentity, ref Session session, out IntPtr engine);
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    private static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr application);
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    private static extern uint FwpmFilterAdd0(IntPtr engine, ref Filter filter, IntPtr securityDescriptor, out ulong filterId);
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    private static extern void FwpmFreeMemory0(ref IntPtr memory);
}
