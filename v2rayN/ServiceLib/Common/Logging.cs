using NLog;
using NLog.Config;
using NLog.Layouts;
using NLog.Targets;

namespace ServiceLib.Common;

public class Logging
{
    private static readonly Logger _logger1 = LogManager.GetLogger("Log1");
    private static readonly Logger _logger2 = LogManager.GetLogger("Log2");
    private static readonly string _run = Guid.NewGuid().ToString("N");
    private static long _started = Environment.TickCount64;
    private static int _rotationMinutes = 60;
    private static int _generation;
    private static readonly object _rotationGate = new();
    private static int _retentionHours = 24;
    private static bool _rolling;

    public static void Setup(bool rolling = false)
    {
        LoggingConfiguration config = new();
        _rolling = rolling;
        FileTarget fileTarget = new() { KeepFileOpen = true };
        config.AddTarget("file", fileTarget);
        fileTarget.Layout = "${longdate}-${level:uppercase=true} ${message}";
        if (rolling)
        {
            var logDirectory = Utils.GetLogPath();
            fileTarget.FileName = Layout.FromMethod(_ => Path.Combine(logDirectory, CurrentFileName()));
            fileTarget.ArchiveAboveSize = 4 * 1024 * 1024;
            fileTarget.ArchiveSuffixFormat = "-{0:000}";
            fileTarget.MaxArchiveFiles = 16;
        }
        else
        {
            fileTarget.FileName = Utils.GetLogPath("${shortdate}.txt");
        }
        config.LoggingRules.Add(new LoggingRule("*", LogLevel.Debug, fileTarget));
        LogManager.Configuration = config;
    }

    public static void ConfigureRetention(VaKoLinkLogSettings? settings)
    {
        var interval = Math.Clamp(settings?.RotationMinutes ?? 60, 1, 1440);
        lock (_rotationGate)
        {
            if (_rotationMinutes != interval)
            {
                _rotationMinutes = interval;
                _started = Environment.TickCount64;
                _generation++;
            }
        }
        _retentionHours = Math.Clamp(settings?.RetentionHours ?? 24, 1, 168);
    }

    private static string CurrentFileName()
    {
        lock (_rotationGate)
        {
            return $"vakolink-{_run}-{_generation}-{(Environment.TickCount64 - _started) / (_rotationMinutes * 60_000L)}.txt";
        }
    }

    public static void Prune()
    {
        if (!_rolling) return;
        try
        {
            var deadline = DateTime.UtcNow.AddHours(-_retentionHours);
            long size = 0;
            foreach (var file in new DirectoryInfo(Utils.GetLogPath()).EnumerateFiles("*.txt")
                .OrderByDescending(file => file.LastWriteTimeUtc))
            {
                if ((file.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                if (System.Text.RegularExpressions.Regex.IsMatch(file.Name, @"^(?:Vaccess_|Verror_|sbox_)?[0-9]{4}-[0-9]{2}-[0-9]{2}\.txt$"))
                {
                    if (file.LastWriteTimeUtc < DateTime.UtcNow.AddDays(-7))
                        DeleteClosedFile(file);
                    continue;
                }
                // Match only this target's filenames. The open segment is always retained.
                if (!System.Text.RegularExpressions.Regex.IsMatch(file.Name, @"^vakolink-[0-9a-f]{32}-[0-9]+-[0-9]+(?:-[0-9]+)?\.txt$"))
                    continue;
                size += file.Length;
                if (file.Name != CurrentFileName() && (file.LastWriteTimeUtc < deadline || size > 64 * 1024 * 1024))
                {
                    DeleteClosedFile(file);
                }
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            NLog.Common.InternalLogger.Warn("Could not prune VaKoLink log files.");
        }
    }

    private static void DeleteClosedFile(FileInfo file)
    {
        try
        {
            using (file.Open(FileMode.Open, FileAccess.Read, FileShare.None)) { }
            file.Delete();
        }
        catch (IOException) { }
    }

    public static void LoggingEnabled(bool enable)
    {
        if (!enable)
        {
            LogManager.SuspendLogging();
        }
    }

    public static void SaveLog(string strContent)
    {
        if (!LogManager.IsLoggingEnabled())
        {
            return;
        }

        _logger1.Info(strContent);
    }

    public static void SaveLog(string strTitle, Exception ex)
    {
        if (!LogManager.IsLoggingEnabled())
        {
            return;
        }

        _logger2.Debug($"{strTitle},{ex.Message}");
        _logger2.Debug(ex.StackTrace);
        if (ex?.InnerException != null)
        {
            _logger2.Error(ex.InnerException);
        }
    }
}
