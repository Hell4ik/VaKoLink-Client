namespace v2rayN.Desktop.Common;

internal static class MacBundledCores
{
    [SupportedOSPlatform("macos")]
    internal static void InstallMissing()
    {
        string sourceDirectory = Utils.GetBaseDirectory("../Resources/bin");
        if (!Directory.Exists(sourceDirectory))
        {
            return;
        }

        string destinationDirectory = Utils.GetBinPath("");
        foreach (string relativePath in new[] { "xray/xray", "xray/geoip.dat", "xray/geosite.dat", "sing_box/sing-box", "mihomo/mihomo" })
        {
            string source = Path.Combine(sourceDirectory, relativePath);
            string destination = Path.Combine(destinationDirectory, relativePath);
            if (!File.Exists(source) || File.Exists(destination))
            {
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            string temporary = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                File.Copy(source, temporary);
                File.SetUnixFileMode(temporary, File.GetUnixFileMode(source));
                File.Move(temporary, destination);
            }
            catch (IOException) when (File.Exists(destination))
            {
                // Another launch populated the user's core directory.
            }
            finally
            {
                File.Delete(temporary);
            }
        }
    }
}
