using System.Security.Cryptography.X509Certificates;

namespace VakoLink.AntiDpi.Windows;

public static class GameComponentTrust
{
    public static bool IsSignedNcImage(string path)
    {
        if (!File.Exists(path) || !AuthenticodeVerifier.IsTrusted(path)) return false;
        using var signed = X509Certificate.CreateFromSignedFile(path);
        using var cert = new X509Certificate2(signed);
        return cert.GetNameInfo(X509NameType.SimpleName, false) == "NC Corporation";
    }
}
