using System.Globalization;
using System.Text.Json;

namespace VaKoLink.Updates;

internal static class ClientUpdateProcess
{
    private static string Root => AppContext.BaseDirectory;
    internal static string Work => UpdatePackage.SafePath(Root, UpdatePackage.WorkDirectory);
    internal static bool IsPortableClient => string.Equals(Environment.ProcessPath,
        Path.Combine(Root, UpdatePackage.ClientName), StringComparison.OrdinalIgnoreCase);

    internal static string CreateTransaction()
    {
        Directory.CreateDirectory(Work);
        var transaction = UpdatePackage.SafePath(Work, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(transaction);
        return transaction;
    }

    internal static bool CanStart()
    {
        var work = Work;
        if (!Directory.Exists(work))
        {
            return true;
        }

        string id;
        using (UpdatePackage.Lock(work))
        {
            var pending = UpdatePackage.SafePath(work, UpdatePackage.PendingName);
            if (!File.Exists(pending))
            {
                return true;
            }
            id = File.ReadAllText(pending);
        }
        if (!UpdatePackage.IsTransactionId(id) || !IsPortableClient)
        {
            throw new InvalidDataException("Не удалось прочитать состояние предыдущего обновления.");
        }
        StartHelper(UpdatePackage.SafePath(work, id), UpdatePackage.RecoverCommand);
        return false;
    }

    internal static (string Text, DateTime SavedAt)? TakeResult()
    {
        var result = UpdatePackage.SafePath(Work, UpdatePackage.ResultName);
        if (!File.Exists(result))
        {
            return null;
        }

        var savedAt = File.GetLastWriteTimeUtc(result);
        var text = File.ReadAllText(result);
        File.Delete(result);
        return (text, savedAt);
    }

    internal static Version? FindPreviousVersion(string result, DateTime savedAt, string installedVersion)
    {
        if (!UpdatePackage.TryParseVersion(installedVersion, out var current))
        {
            return null;
        }
        var marker = result.IndexOf(UpdatePackage.PreviousVersionPrefix, StringComparison.Ordinal);
        if (marker >= 0 && UpdatePackage.TryParseVersion(
                result[(marker + UpdatePackage.PreviousVersionPrefix.Length)..].TrimEnd('.'), out var previous) &&
            previous < current)
        {
            return previous;
        }

        // Published older helpers leave the previous executable in the completed transaction.
        var candidates = new List<(Version Version, TimeSpan Age)>();
        foreach (var directory in Directory.EnumerateDirectories(Work))
        {
            var id = Path.GetFileName(directory);
            if (!UpdatePackage.IsTransactionId(id))
            {
                continue;
            }
            try
            {
                var staged = UpdatePackage.SafePath(Work, $"{id}/new");
                var backup = UpdatePackage.SafePath(Work, $"{id}/backup/{UpdatePackage.ClientName}");
                if (!Directory.Exists(staged) || File.Exists(UpdatePackage.SafePath(staged, UpdatePackage.ClientName)) ||
                    !File.Exists(backup))
                {
                    continue;
                }
                var age = savedAt - Directory.GetLastWriteTimeUtc(staged);
                if (age < TimeSpan.FromSeconds(-2) || age > TimeSpan.FromMinutes(5))
                {
                    continue;
                }
                var info = FileVersionInfo.GetVersionInfo(backup);
                var version = new Version(info.FileMajorPart, info.FileMinorPart, info.FileBuildPart, info.FilePrivatePart);
                if (info.ProductName == "VaKoLink" && version < current)
                {
                    candidates.Add((version, age.Duration()));
                }
            }
            catch (IOException)
            {
                // An unrelated old transaction may have been cleaned up in the meantime.
            }
        }
        return candidates.OrderBy(candidate => candidate.Age).Select(candidate => (Version?)candidate.Version).FirstOrDefault();
    }

    internal static VaKoLinkResumeState? TakeResume(string[] args)
    {
        if (args is not [UpdatePackage.ResumeCommand, var id] || !UpdatePackage.IsTransactionId(id))
        {
            return null;
        }
        var marker = UpdatePackage.SafePath(Work, $"{id}/{UpdatePackage.ResumeName}");
        if (!File.Exists(marker))
        {
            return null;
        }
        var json = File.ReadAllText(marker);
        File.Delete(marker);
        return JsonSerializer.Deserialize<VaKoLinkResumeState>(json);
    }

    internal static void StartInstallation(string transaction, ClientRelease release, VaKoLinkResumeState? resume)
    {
        if (!IsPortableClient)
        {
            throw new InvalidOperationException("Для установки запустите VaKoLink.exe из портативной папки.");
        }
        var helper = UpdatePackage.SafePath(transaction, UpdatePackage.HelperName);
        File.Copy(UpdatePackage.SafePath(Root, UpdatePackage.HelperName), helper, overwrite: true);
        if (resume is not null)
        {
            UpdatePackage.WriteMarker(transaction, UpdatePackage.ResumeName, JsonSerializer.Serialize(resume));
        }
        else
        {
            File.Delete(UpdatePackage.SafePath(transaction, UpdatePackage.ResumeName));
        }
        StartHelper(transaction, UpdatePackage.InstallCommand, release.Label, release.Sha256);
    }

    private static void StartHelper(string transaction, string command, params string[] arguments)
    {
        using var client = Process.GetCurrentProcess();
        var start = new ProcessStartInfo(UpdatePackage.SafePath(transaction, UpdatePackage.HelperName))
        {
            WorkingDirectory = transaction,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        start.ArgumentList.Add(command);
        start.ArgumentList.Add(client.Id.ToString(CultureInfo.InvariantCulture));
        start.ArgumentList.Add(client.StartTime.ToUniversalTime().Ticks.ToString(CultureInfo.InvariantCulture));
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }
        using var helper = Process.Start(start) ?? throw new IOException("Не удалось запустить установщик VaKoLink.");
    }
}
