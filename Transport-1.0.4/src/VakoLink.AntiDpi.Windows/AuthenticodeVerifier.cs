using System.Runtime.InteropServices;

namespace VakoLink.AntiDpi.Windows;

internal static class AuthenticodeVerifier
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FileInfo
    {
        public uint Size;
        [MarshalAs(UnmanagedType.LPWStr)] public string Path;
        public IntPtr File;
        public IntPtr KnownSubject;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct TrustData
    {
        public uint Size;
        public IntPtr PolicyCallback;
        public IntPtr SipClient;
        public uint UIChoice;
        public uint Revocation;
        public uint UnionChoice;
        public IntPtr File;
        public uint StateAction;
        public IntPtr State;
        public IntPtr Url;
        public uint ProviderFlags;
        public uint UIContext;
    }
    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref TrustData data);

    internal static bool IsTrusted(string path)
    {
        var file = new FileInfo { Size = (uint)Marshal.SizeOf<FileInfo>(), Path = path };
        var filePointer = Marshal.AllocHGlobal(Marshal.SizeOf<FileInfo>());
        Marshal.StructureToPtr(file, filePointer, false);
        var data = new TrustData
        {
            Size = (uint)Marshal.SizeOf<TrustData>(),
            UIChoice = 2,
            UnionChoice = 1,
            File = filePointer,
            StateAction = 1,
            ProviderFlags = 0x1000 // cache-only; no network retrieval
        };
        var action = new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
        try { return WinVerifyTrust(new IntPtr(-1), ref action, ref data) == 0; }
        finally
        {
            data.StateAction = 2;
            _ = WinVerifyTrust(new IntPtr(-1), ref action, ref data);
            Marshal.DestroyStructure<FileInfo>(filePointer);
            Marshal.FreeHGlobal(filePointer);
        }
    }
}
