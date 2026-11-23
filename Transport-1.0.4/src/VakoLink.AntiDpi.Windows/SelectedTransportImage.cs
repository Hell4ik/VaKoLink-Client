namespace VakoLink.AntiDpi.Windows;

public sealed record SelectedTransportImage(string Path, string Sha256)
{
    public static SelectedTransportImage Verify(string path)
    {
        TunPrivateStore.VerifyImagePath(path);
        if (!string.Equals(System.IO.Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(path))
            throw new IOException("SELECTED_APPLICATION_MISSING");

        using var image = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (!AuthenticodeVerifier.IsTrusted(path))
            throw new IOException("SELECTED_APPLICATION_UNTRUSTED");

        return new(path, AionTunPlan.FileHash(path));
    }
}
