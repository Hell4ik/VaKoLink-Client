using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;

namespace VaKoLink.Updates;

internal static class UpdatePackage
{
    internal const string WorkDirectory = ".vakolink-update";
    internal const string ArchiveName = "package.zip";
    internal const string HelperName = "AmazTool.exe";
    internal const string ClientName = "VaKoLink.exe";
    internal const string PendingName = "pending.txt";
    internal const string ResultName = "result.txt";
    internal const string InstallCommand = "--vakolink-install";
    internal const string RecoverCommand = "--vakolink-recover";
    internal const string ResumeCommand = "--vakolink-resume";
    internal const string ResumeName = "resume.json";
    internal const long MaxArchiveSize = 512L * 1024 * 1024;
    private const long MaxUnpackedSize = 1024L * 1024 * 1024;

    // Only files owned by the portable application. Keep component binaries in bin/ independent.
    internal static IReadOnlyList<string> Files { get; } = Array.AsReadOnly(new[]
    {
        "D3DCompiler_47_cor3.dll", "e_sqlite3.dll", "libSkiaSharp.dll", "PenImc_cor3.dll",
        "PresentationNative_cor3.dll", "vcruntime140_cor3.dll", "wpfgfx_cor3.dll",
        "core/sing-box.exe", "tools/Discover-LocalProxy.ps1", "tools/ProxyNetworkState.ps1",
        "LICENSE.txt", HelperName, ClientName
    });

    internal static bool TryParseVersion(string? value, out Version version)
    {
        version = new Version(0, 0, 0, 0);
        if (value is null || value.Length > 40 || !Version.TryParse(value, out var parsed) ||
            value != parsed.ToString())
        {
            return false;
        }
        version = new Version(parsed.Major, parsed.Minor, Math.Max(0, parsed.Build), Math.Max(0, parsed.Revision));
        return true;
    }

    internal static string AssetName(string version) => $"VaKoLink-v{version}-windows-x64-update.zip";

    internal static bool IsSha256(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    internal static bool IsTransactionId(string id) =>
        Guid.TryParseExact(id, "N", out var parsed) && parsed.ToString("N") == id;

    internal static string SafePath(string root, string relative)
    {
        var path = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        RequireOrdinaryPath(path);
        foreach (var part in relative.Split('/'))
        {
            if (part.Length == 0 || part is "." or ".." || part.IndexOfAny(['\\', ':']) >= 0)
            {
                throw new InvalidDataException("Недопустимый путь обновления.");
            }
            path = Path.Combine(path, part);
            RequireOrdinaryPath(path);
        }
        return path;
    }

    private static void RequireOrdinaryPath(string path)
    {
        try
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException($"Путь обновления указывает на ссылку: {Path.GetFileName(path)}.");
            }
        }
        catch (FileNotFoundException) { }
        catch (DirectoryNotFoundException) { }
    }

    internal static FileStream Lock(string work) =>
        new(SafePath(work, "install.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);

    internal static void WriteMarker(string root, string name, string value)
    {
        var target = SafePath(root, name);
        var temp = SafePath(root, name + ".tmp");
        using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(value);
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }
        File.Move(temp, target, overwrite: true);
    }

    internal static async Task<bool> VerifyAsync(Stream archive, string sha256, CancellationToken token = default)
    {
        if (!IsSha256(sha256) || archive.Length is <= 0 or > MaxArchiveSize)
        {
            return false;
        }
        var digest = await SHA256.HashDataAsync(archive, token);
        return CryptographicOperations.FixedTimeEquals(digest, Convert.FromHexString(sha256));
    }

    internal static void Extract(Stream archive, string destination, Version expectedVersion)
    {
        using var zip = new ZipArchive(archive, ZipArchiveMode.Read, leaveOpen: true);
        if (zip.Entries.Count != Files.Count)
        {
            throw new InvalidDataException("Неверный состав пакета VaKoLink.");
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        long total = 0;
        foreach (var entry in zip.Entries)
        {
            if (!Files.Contains(entry.FullName, StringComparer.Ordinal) || !seen.Add(entry.FullName) ||
                entry.Length <= 0 || (entry.ExternalAttributes & 0xF0000000u) == 0xA0000000u ||
                (entry.ExternalAttributes & (int)FileAttributes.ReparsePoint) != 0 ||
                entry.Length > MaxUnpackedSize - total)
            {
                throw new InvalidDataException("Недопустимый файл в пакете VaKoLink.");
            }
            total += entry.Length;
            var path = SafePath(destination, entry.FullName);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            using var input = entry.Open();
            using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            var remaining = entry.Length;
            var buffer = new byte[128 * 1024];
            while (remaining > 0)
            {
                var read = input.Read(buffer, 0, (int)Math.Min(remaining, buffer.Length));
                if (read == 0)
                {
                    throw new InvalidDataException("В пакете повреждён файл VaKoLink.");
                }
                output.Write(buffer, 0, read);
                remaining -= read;
            }
            if (input.ReadByte() != -1)
            {
                throw new InvalidDataException("Размер файла VaKoLink не совпадает с содержимым пакета.");
            }
        }

        var executable = SafePath(destination, ClientName);
        var info = FileVersionInfo.GetVersionInfo(executable);
        var version = new Version(info.FileMajorPart, info.FileMinorPart, info.FileBuildPart, info.FilePrivatePart);
        using var reader = new BinaryReader(File.OpenRead(executable));
        if (reader.BaseStream.Length < 64 || reader.ReadUInt16() != 0x5A4D)
        {
            throw new InvalidDataException("В пакете отсутствует исполняемый файл VaKoLink.");
        }
        reader.BaseStream.Position = 60;
        var peOffset = reader.ReadInt32();
        if (peOffset < 64 || peOffset > reader.BaseStream.Length - 6)
        {
            throw new InvalidDataException("В пакете повреждён исполняемый файл VaKoLink.");
        }
        reader.BaseStream.Position = peOffset;
        if (reader.ReadUInt32() != 0x00004550 || reader.ReadUInt16() != 0x8664 ||
            info.ProductName != "VaKoLink" || version != expectedVersion)
        {
            throw new InvalidDataException("Версия или архитектура VaKoLink.exe не соответствует манифесту.");
        }
    }
}
