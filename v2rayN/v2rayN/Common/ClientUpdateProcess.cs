using System.Globalization;

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

    internal static string? TakeResult()
    {
        var result = UpdatePackage.SafePath(Work, UpdatePackage.ResultName);
        if (!File.Exists(result))
        {
            return null;
        }

        var text = File.ReadAllText(result);
        File.Delete(result);
        return text;
    }

    internal static void StartInstallation(string transaction, ClientRelease release)
    {
        if (!IsPortableClient)
        {
            throw new InvalidOperationException("Для установки запустите VaKoLink.exe из портативной папки.");
        }
        var helper = UpdatePackage.SafePath(transaction, UpdatePackage.HelperName);
        File.Copy(UpdatePackage.SafePath(Root, UpdatePackage.HelperName), helper, overwrite: true);
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
