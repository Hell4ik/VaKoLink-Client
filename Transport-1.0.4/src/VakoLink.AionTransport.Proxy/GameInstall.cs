using System.IO;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using VakoLink.AntiDpi.Windows;

namespace VakoLink.AionTransport.Proxy;

public sealed record GameInstall(string Root, string Main, string SteamId, string Sha256)
{
    public static GameInstall FromRoot(string root, string id)
    {
        if (!Regex.IsMatch(id, "^[0-9]{3,12}$")) throw new IOException("AION_STEAM_LAUNCHER_UNKNOWN");
        string path = Path.Combine(Path.GetFullPath(root), @"Aion2\Binaries\Win64\AION2.exe");
        TunPrivateStore.VerifyImagePath(path);
        if (!File.Exists(path) || !GameComponentTrust.IsSignedNcImage(path)) throw new IOException("AION_SIGNATURE_NOT_TRUSTED");
        return new(Path.GetFullPath(root), path, id, AionTunPlan.FileHash(path));
    }
    public static IReadOnlyList<GameInstall> Find()
    {
        var libraries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using var steam = Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam");
        foreach (string? path in new[] { steam?.GetValue("SteamPath") as string, steam?.GetValue("InstallPath") as string }) if (!string.IsNullOrEmpty(path)) libraries.Add(Path.GetFullPath(path));
        using var machine = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Valve\Steam");
        if (machine?.GetValue("InstallPath") is string installation) libraries.Add(Path.GetFullPath(installation));
        foreach (var lib in libraries.ToArray())
        {
            string file = Path.Combine(lib, @"steamapps\libraryfolders.vdf");
            if (File.Exists(file) && new FileInfo(file).Length < 256000)
                foreach (Match m in Regex.Matches(File.ReadAllText(file), "\"path\"\\s+\"([^\"]+)\"")) libraries.Add(Path.GetFullPath(m.Groups[1].Value.Replace("\\\\", "\\")));
        }
        var games = new List<GameInstall>();
        foreach (var lib in libraries.Take(32))
        {
            string apps = Path.Combine(lib, "steamapps"); if (!Directory.Exists(apps)) continue;
            foreach (string file in Directory.EnumerateFiles(apps, "appmanifest_*.acf").Take(1024))
            {
                if (new FileInfo(file).Length > 128000) continue; string text = File.ReadAllText(file);
                string name = Value(text, "name"), dir = Value(text, "installdir"), id = Value(text, "appid");
                if (!name.Equals("AION 2", StringComparison.OrdinalIgnoreCase) && !name.Equals("AION2", StringComparison.OrdinalIgnoreCase)) continue;
                if (string.IsNullOrEmpty(dir) || Path.GetFileName(dir) != dir) continue;
                try { games.Add(FromRoot(Path.Combine(apps, "common", dir), id)); } catch (IOException) { }
            }
        }
        return games.DistinctBy(g => g.Main, StringComparer.OrdinalIgnoreCase).ToArray();
    }
    private static string Value(string text, string key) => Regex.Match(text, "\"" + key + "\"\\s+\"([^\"]+)\"", RegexOptions.IgnoreCase).Groups[1].Value;
    public void VerifyUnchanged()
    {
        TunPrivateStore.VerifyImagePath(Main);
        if (!GameComponentTrust.IsSignedNcImage(Main)) throw new IOException("AION_SIGNATURE_NOT_TRUSTED");
        if (AionTunPlan.FileHash(Main) != Sha256) throw new IOException("AION_UPDATED_RECHECK_REQUIRED");
    }
    public override string ToString() => "Aion 2 · Steam";
}
