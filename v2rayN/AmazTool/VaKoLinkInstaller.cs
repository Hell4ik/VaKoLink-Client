using System.Diagnostics;
using System.Globalization;
using VaKoLink.Updates;

namespace AmazTool;

internal static class VaKoLinkInstaller
{
    internal static async Task<int> RunAsync(string[] args)
    {
        var transaction = Path.GetDirectoryName(Environment.ProcessPath)!;
        var id = Path.GetFileName(transaction);
        var work = Path.GetDirectoryName(transaction)!;
        var root = Path.GetDirectoryName(work)!;
        var recovering = args[0] == UpdatePackage.RecoverCommand;
        if (!UpdatePackage.IsTransactionId(id) || Path.GetFileName(work) != UpdatePackage.WorkDirectory)
        {
            throw new InvalidOperationException("Установщик запущен вне каталога обновления VaKoLink.");
        }
        UpdatePackage.SafePath(root, $"{UpdatePackage.WorkDirectory}/{id}/{UpdatePackage.HelperName}");

        if (args.Length != (recovering ? 3 : 5) ||
            !int.TryParse(args[1], NumberStyles.None, CultureInfo.InvariantCulture, out var parentId) || parentId <= 0 ||
            !long.TryParse(args[2], NumberStyles.None, CultureInfo.InvariantCulture, out var parentStarted) || parentStarted <= 0)
        {
            throw new InvalidDataException("Неверные параметры установки VaKoLink.");
        }

        var executable = UpdatePackage.SafePath(root, UpdatePackage.ClientName);
        var pending = UpdatePackage.SafePath(work, UpdatePackage.PendingName);
        string report;
        bool restart;
        int exitCode;
        using (await WaitForLockAsync(work))
        {
            // Never touch the package or the installation if the running client failed to exit.
            await WaitForClientAsync(executable, parentId, parentStarted);
            try
            {
                if (recovering)
                {
                    if (!File.Exists(pending) || File.ReadAllText(pending) != id)
                    {
                        throw new InvalidOperationException("Не найдена незавершённая установка VaKoLink.");
                    }
                    RollBack(root, transaction);
                    File.Delete(pending);
                    report = "Обновление VaKoLink прервалось. Прежняя версия восстановлена.";
                }
                else
                {
                    if (!UpdatePackage.TryParseVersion(args[3], out var expected))
                    {
                        throw new InvalidDataException("Неверная версия пакета.");
                    }
                    await InstallAsync(root, work, transaction, expected, args[4]);
                    report = $"{UpdatePackage.InstalledResultPrefix}{args[3]}.";
                }
                exitCode = 0;
                restart = true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex);
                restart = !File.Exists(pending);
                report = restart
                    ? "Обновление не установлено. Прежняя версия сохранена."
                    : $"Не удалось восстановить VaKoLink. Резервная копия: {Path.Combine(transaction, "backup")}. {ex.Message}";
                exitCode = 1;
            }

            try
            {
                UpdatePackage.WriteMarker(work, UpdatePackage.ResultName, report);
                if (restart)
                {
                    File.Delete(UpdatePackage.SafePath(transaction, UpdatePackage.ArchiveName));
                }
            }
            catch (IOException ex)
            {
                Console.Error.WriteLine(ex.Message);
            }
        }

        Console.WriteLine(report);
        if (restart)
        {
            var start = new ProcessStartInfo(executable)
            {
                WorkingDirectory = root,
                UseShellExecute = false
            };
            if (File.Exists(UpdatePackage.SafePath(transaction, UpdatePackage.ResumeName)))
            {
                start.ArgumentList.Add(UpdatePackage.ResumeCommand);
                start.ArgumentList.Add(id);
            }
            using var client = Process.Start(start);
        }
        return exitCode;
    }

    internal static async Task InstallAsync(string root, string work, string transaction, Version version, string sha256)
    {
        var pending = UpdatePackage.SafePath(work, UpdatePackage.PendingName);
        if (File.Exists(pending))
        {
            throw new InvalidOperationException("Сначала нужно восстановить прерванное обновление VaKoLink.");
        }
        var installed = FileVersionInfo.GetVersionInfo(UpdatePackage.SafePath(root, UpdatePackage.ClientName));
        if (version <= new Version(installed.FileMajorPart, installed.FileMinorPart, installed.FileBuildPart, installed.FilePrivatePart))
        {
            throw new InvalidOperationException("Этот пакет не новее установленной версии VaKoLink.");
        }

        var staged = UpdatePackage.SafePath(transaction, "new");
        var backup = UpdatePackage.SafePath(transaction, "backup");
        Directory.CreateDirectory(staged);
        Directory.CreateDirectory(backup);
        await using (var package = File.OpenRead(UpdatePackage.SafePath(transaction, UpdatePackage.ArchiveName)))
        {
            if (!await UpdatePackage.VerifyAsync(package, sha256))
            {
                throw new InvalidDataException("SHA-256 пакета VaKoLink не совпадает с манифестом.");
            }
            package.Position = 0;
            UpdatePackage.Extract(package, staged, version);
        }

        foreach (var file in UpdatePackage.Files)
        {
            var destination = UpdatePackage.SafePath(root, file);
            if (File.Exists(destination))
            {
                var original = UpdatePackage.SafePath(backup, file);
                Directory.CreateDirectory(Path.GetDirectoryName(original)!);
                File.Copy(destination, original);
            }
        }

        UpdatePackage.WriteMarker(work, UpdatePackage.PendingName, Path.GetFileName(transaction));
        try
        {
            foreach (var file in UpdatePackage.Files)
            {
                var destination = UpdatePackage.SafePath(root, file);
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                File.Move(UpdatePackage.SafePath(staged, file), destination,
                    overwrite: File.Exists(UpdatePackage.SafePath(backup, file)));
            }
            File.Delete(pending);
        }
        catch
        {
            RollBack(root, transaction);
            File.Delete(pending);
            throw;
        }
    }

    private static void RollBack(string root, string transaction)
    {
        var staged = UpdatePackage.SafePath(transaction, "new");
        var backup = UpdatePackage.SafePath(transaction, "backup");
        if (!Directory.Exists(staged) || !Directory.Exists(backup))
        {
            throw new DirectoryNotFoundException("Отсутствуют файлы для восстановления обновления.");
        }
        var restore = UpdatePackage.SafePath(transaction, "restore");
        foreach (var file in UpdatePackage.Files.Reverse())
        {
            // A same-volume move removes the staged file only after replacing the destination.
            if (File.Exists(UpdatePackage.SafePath(staged, file)))
            {
                continue;
            }
            var destination = UpdatePackage.SafePath(root, file);
            var original = UpdatePackage.SafePath(backup, file);
            if (File.Exists(original))
            {
                var temporary = UpdatePackage.SafePath(restore, file);
                Directory.CreateDirectory(Path.GetDirectoryName(temporary)!);
                File.Copy(original, temporary, overwrite: true);
                File.Move(temporary, destination, overwrite: true);
            }
            else
            {
                File.Delete(destination);
            }
        }
    }

    private static async Task<FileStream> WaitForLockAsync(string work)
    {
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                return UpdatePackage.Lock(work);
            }
            catch (IOException) when (attempt < 40)
            {
                await Task.Delay(100);
            }
        }
    }

    private static async Task WaitForClientAsync(string executable, int parentId, long parentStarted)
    {
        Process parent;
        try
        {
            parent = Process.GetProcessById(parentId);
        }
        catch (ArgumentException)
        {
            return;
        }
        using (parent)
        {
            if (parent.HasExited || parent.StartTime.ToUniversalTime().Ticks != parentStarted)
            {
                return;
            }
            if (!string.Equals(parent.MainModule?.FileName, executable, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Исполняемый файл закрываемого клиента не совпадает с VaKoLink.exe.");
            }
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            await parent.WaitForExitAsync(timeout.Token);
        }
    }
}
