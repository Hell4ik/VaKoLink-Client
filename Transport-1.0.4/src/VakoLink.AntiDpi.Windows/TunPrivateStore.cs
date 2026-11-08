using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;
using System.Security.Cryptography;
using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public static class TunPrivateStore
{
    public static void VerifyImagePath(string path)
    {
        if (!Path.IsPathFullyQualified(path) || path.StartsWith(@"\\", StringComparison.Ordinal)) throw new IOException("TUN_IMAGE_PATH_INVALID");
        for (string? p = Path.GetFullPath(path); p is not null; p = Path.GetDirectoryName(p))
            if ((File.Exists(p) || Directory.Exists(p)) && (File.GetAttributes(p) & FileAttributes.ReparsePoint) != 0) throw new IOException("TUN_IMAGE_REPARSE");
    }
    public static string Root => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VakoLink", "AionTransport");
    public static void EnsurePrivate(string path)
    {
        for (string? p = Path.GetFullPath(path); p is not null; p = Path.GetDirectoryName(p))
            if (Directory.Exists(p) && (File.GetAttributes(p) & FileAttributes.ReparsePoint) != 0) throw new IOException("TUN_STORAGE_REPARSE");
        Directory.CreateDirectory(path);
        using var user = WindowsIdentity.GetCurrent(); var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { user.User!, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) })
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(acl);
    }
    [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Length; public IntPtr Pointer; }
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool CryptProtectData(ref Blob b, string? description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob result);
    [DllImport("crypt32.dll", SetLastError = true)] private static extern bool CryptUnprotectData(ref Blob b, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob result);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr p);
    public static byte[] Protect(byte[] bytes, bool decrypt = false)
    {
        var input = new Blob { Length = bytes.Length, Pointer = Marshal.AllocHGlobal(bytes.Length) }; Blob result = default;
        try
        {
            Marshal.Copy(bytes, 0, input.Pointer, bytes.Length);
            bool ok = decrypt ? CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out result)
                : CryptProtectData(ref input, "VakoLink isolated Aion transport", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out result);
            if (!ok) throw new IOException("TUN_DPAPI_FAILED"); var data = new byte[result.Length]; Marshal.Copy(result.Pointer, data, 0, data.Length); return data;
        }
        finally { Marshal.Copy(new byte[bytes.Length], 0, input.Pointer, bytes.Length); Marshal.FreeHGlobal(input.Pointer); if (result.Pointer != IntPtr.Zero) { Marshal.Copy(new byte[result.Length], 0, result.Pointer, result.Length); LocalFree(result.Pointer); } }
    }
    public static void WriteProtected(string path, string json)
    { var b = Encoding.UTF8.GetBytes(json); try { File.WriteAllBytes(path, Protect(b)); } finally { CryptographicOperations.ZeroMemory(b); } }
    public static JsonObject ReadProtected(string path)
    { var b = Protect(File.ReadAllBytes(path), true); try { return JsonNode.Parse(b)!.AsObject(); } finally { CryptographicOperations.ZeroMemory(b); } }
    public static void Prepare(string main)
    {
        EnsurePrivate(Root); string target = Path.Combine(Root, AionTunPlan.CapsuleFile); if (File.Exists(target)) throw new IOException("TUN_PRIVATE_COPY_ALREADY_EXISTS");
        if (File.Exists(Path.Combine(Root, "active-operation.json"))) throw new IOException("TUN_PREVIOUS_OPERATION_REQUIRES_RECOVERY");
        VerifyImagePath(main); VerifyImagePath(AionTunPlan.CorePath);
        using var coreLock = new FileStream(AionTunPlan.CorePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var mainLock = new FileStream(main, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (AionTunPlan.FileHash(AionTunPlan.CorePath) != AionTunPlan.CoreSha256 || !GameComponentTrust.IsSignedNcImage(main)) throw new IOException("TUN_SOURCE_CHANGED");
        // Rebind ONLY the approved updated client; preserve the already approved node and the old capsule verbatim.
        var capsule = ReadProtected(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VakoLink", "AntiDpi", "TransportPrivate", "germany-node-r4191.dpapi"));
        if ((string?)capsule["CoreSHA256"] != AionTunPlan.CoreSha256 || (string?)capsule["SourceSHA256"] != AionTunPlan.SourceRuntimeSha256
            || !string.Equals((string?)capsule["MainPath"], main, StringComparison.OrdinalIgnoreCase)
            || (string?)capsule["MainSHA256"] != AionTunPlan.ClientSha256) throw new IOException("TUN_LEGACY_CAPSULE_CHANGED");
        capsule["Version"] = AionTunPlan.Version; capsule["MainSHA256"] = AionTunPlan.FileHash(main);
        capsule["ReboundUtc"] = DateTimeOffset.UtcNow.ToString("O"); capsule["RebindingBasis"] = "Same registered fixed image path; new exact SHA256; valid NC Corporation Authenticode; legacy capsule preserved";
        WriteProtected(target, capsule.ToJsonString());
    }
    public static JsonObject Load() => ReadProtected(Path.Combine(Root, AionTunPlan.CapsuleFile));
    public static void RebindApprovedClient(string main)
    {
        if (File.Exists(Path.Combine(Root, "active-operation.json")) || System.Diagnostics.Process.GetProcessesByName("AION2").Length != 0
            || System.Diagnostics.Process.GetProcessesByName("sing-box").Length != 0) throw new IOException("TUN_STOP_BEFORE_REBIND");
        VerifyImagePath(main); EnsurePrivate(Root); var capsule = Load();
        if (!string.Equals((string?)capsule["MainPath"], main, StringComparison.OrdinalIgnoreCase)) throw new IOException("TUN_AION_PATH_CHANGED");
        using var imageLock = new FileStream(main, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (!GameComponentTrust.IsSignedNcImage(main)) throw new IOException("TUN_AION_SIGNATURE_UNTRUSTED");
        string sha = AionTunPlan.FileHash(main);
        string history = Path.Combine(Root, "binding-" + Guid.NewGuid().ToString("N") + ".dpapi");
        File.Copy(Path.Combine(Root, AionTunPlan.CapsuleFile), history);
        capsule["PreviousMainSHA256"] = (string?)capsule["MainSHA256"]; capsule["MainSHA256"] = sha;
        capsule["ReboundUtc"] = DateTimeOffset.UtcNow.ToString("O");
        string temporary = Path.Combine(Root, "binding-new.dpapi"); WriteProtected(temporary, capsule.ToJsonString());
        File.Move(temporary, Path.Combine(Root, AionTunPlan.CapsuleFile), true);
    }
}
