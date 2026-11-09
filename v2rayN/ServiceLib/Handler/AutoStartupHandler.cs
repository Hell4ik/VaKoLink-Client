using System.Security.Principal;

namespace ServiceLib.Handler;

public static class AutoStartupHandler
{
    private static readonly string _tag = "AutoStartupHandler";

    public static async Task<bool> UpdateTask(Config config)
    {
        if (Utils.IsWindows())
        {
            await ClearTaskWindows();

            if (config.GuiItem.AutoRun)
            {
                await SetTaskWindows();
            }
        }
        else if (Utils.IsLinux())
        {
            await ClearTaskLinux();

            if (config.GuiItem.AutoRun)
            {
                await SetTaskLinux();
            }
        }
        else if (Utils.IsMacOS())
        {
            await ClearTaskOSX();

            if (config.GuiItem.AutoRun)
            {
                await SetTaskOSX();
            }
        }

        return true;
    }

    #region Windows

    [SupportedOSPlatform("windows")]
    private static async Task ClearTaskWindows()
    {
        var autoRunName = GetAutoRunNameWindows();
        WindowsUtils.RegWriteValue(Global.AutoRunRegPath, autoRunName, "");
        if (Utils.IsAdministrator())
        {
            AutoStartTaskService(autoRunName, "", "");
        }

        await Task.CompletedTask;
    }

    [SupportedOSPlatform("windows")]
    private static async Task SetTaskWindows()
    {
        try
        {
            var autoRunName = GetAutoRunNameWindows();
            var exePath = Utils.GetExePath();
            var argument = AppManager.Instance.UseVaKoLinkProfile ? Global.VaKoLinkLogonArgument : null;
            if (Utils.IsAdministrator())
            {
                AutoStartTaskService(autoRunName, exePath, "", argument);
            }
            else
            {
                WindowsUtils.RegWriteValue(Global.AutoRunRegPath, autoRunName,
                    argument is null ? exePath.AppendQuotes() : $"{exePath.AppendQuotes()} {argument}");
            }
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
        }
        await Task.CompletedTask;
    }

    /// <summary>
    /// Auto Start via TaskService
    /// </summary>
    /// <param name="taskName"></param>
    /// <param name="fileName"></param>
    /// <param name="description"></param>
    /// <exception cref="ArgumentNullException"></exception>
    [SupportedOSPlatform("windows")]
    public static void AutoStartTaskService(string taskName, string fileName, string description, string? arguments = null)
    {
        if (taskName.IsNullOrEmpty())
        {
            return;
        }

        var logonUser = WindowsIdentity.GetCurrent().Name;
        using var taskService = new Microsoft.Win32.TaskScheduler.TaskService();
        if (fileName.IsNullOrEmpty())
        {
            taskService.RootFolder.DeleteTask(taskName, exceptionOnNotExists: false);
            return;
        }

        var task = taskService.NewTask();
        task.RegistrationInfo.Description = description;
        task.Settings.DisallowStartIfOnBatteries = false;
        task.Settings.StopIfGoingOnBatteries = false;
        task.Settings.RunOnlyIfIdle = false;
        task.Settings.IdleSettings.StopOnIdleEnd = false;
        task.Settings.ExecutionTimeLimit = TimeSpan.Zero;
        task.Settings.Priority = ProcessPriorityClass.Normal;
        task.Triggers.Add(new Microsoft.Win32.TaskScheduler.LogonTrigger { UserId = logonUser });
        task.Principal.RunLevel = Microsoft.Win32.TaskScheduler.TaskRunLevel.Highest;
        task.Actions.Add(new Microsoft.Win32.TaskScheduler.ExecAction(fileName, arguments, Path.GetDirectoryName(fileName)));

        taskService.RootFolder.RegisterTaskDefinition(taskName, task);
    }

    [SupportedOSPlatform("windows")]
    public static void EnsureVaKoLinkLogonTask(Config config)
    {
        var exe = Utils.GetExePath();
        if (!config.GuiItem.AutoRun || !Utils.IsAdministrator() ||
            !string.Equals(Path.GetFileName(exe), "VaKoLink.exe", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }
        try
        {
            var name = GetAutoRunNameWindows();
            using var service = new Microsoft.Win32.TaskScheduler.TaskService();
            using var task = service.GetTask(name);
            if (task?.Definition.Actions.FirstOrDefault() is Microsoft.Win32.TaskScheduler.ExecAction action &&
                string.Equals(action.Path.Trim('"'), exe, StringComparison.OrdinalIgnoreCase) &&
                action.Arguments == Global.VaKoLinkLogonArgument)
            {
                return;
            }
            AutoStartTaskService(name, exe, "VaKoLink", Global.VaKoLinkLogonArgument);
            WindowsUtils.RegWriteValue(Global.AutoRunRegPath, name, "");
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
        }
    }

    private static string GetAutoRunNameWindows()
    {
        return $"{Global.AutoRunName}_{Utils.GetMd5(Utils.StartupPath())}";
    }

    #endregion Windows

    #region Linux

    [SupportedOSPlatform("linux")]
    private static async Task ClearTaskLinux()
    {
        try
        {
            File.Delete(GetHomePathLinux());
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
        }
        await Task.CompletedTask;
    }

    [SupportedOSPlatform("linux")]
    private static async Task SetTaskLinux()
    {
        try
        {
            var linuxConfig = EmbedUtils.GetEmbedText(Global.LinuxAutostartConfig);
            if (linuxConfig.IsNotEmpty())
            {
                linuxConfig = linuxConfig.Replace("$ExecPath$", Utils.GetExePath());
                Logging.SaveLog(linuxConfig);

                var homePath = GetHomePathLinux();
                await File.WriteAllTextAsync(homePath, linuxConfig);
            }
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
        }
    }

    [SupportedOSPlatform("linux")]
    private static string GetHomePathLinux()
    {
        var homePath = Path.Combine(Utils.GetHomePath(), ".config", "autostart", $"{Global.AppName}.desktop");
        Directory.CreateDirectory(Path.GetDirectoryName(homePath));
        return homePath;
    }

    #endregion Linux

    #region macOS

    [SupportedOSPlatform("macos")]
    private static async Task ClearTaskOSX()
    {
        try
        {
            var launchAgentPath = GetLaunchAgentPathMacOS();
            if (File.Exists(launchAgentPath))
            {
                var args = new[] { "-c", $"launchctl unload -w \"{launchAgentPath}\"" };
                await Utils.GetCliWrapOutput(Global.LinuxBash, args);

                File.Delete(launchAgentPath);
            }
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
        }
    }

    [SupportedOSPlatform("macos")]
    private static async Task SetTaskOSX()
    {
        try
        {
            var plistContent = GenerateLaunchAgentPlist();
            var launchAgentPath = GetLaunchAgentPathMacOS();
            await File.WriteAllTextAsync(launchAgentPath, plistContent);

            var args = new[] { "-c", $"launchctl load -w \"{launchAgentPath}\"" };
            await Utils.GetCliWrapOutput(Global.LinuxBash, args);
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
        }
    }

    [SupportedOSPlatform("macos")]
    private static string GetLaunchAgentPathMacOS()
    {
        var homePath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var launchAgentPath = Path.Combine(homePath, "Library", "LaunchAgents", $"{Global.AppName}-LaunchAgent.plist");
        Directory.CreateDirectory(Path.GetDirectoryName(launchAgentPath));
        return launchAgentPath;
    }

    [SupportedOSPlatform("macos")]
    private static string GenerateLaunchAgentPlist()
    {
        var exePath = Utils.GetExePath();
        var appName = Path.GetFileNameWithoutExtension(exePath);
        return $@"<?xml version=""1.0"" encoding=""UTF-8""?>
<!DOCTYPE plist PUBLIC ""-//Apple//DTD PLIST 1.0//EN"" ""http://www.apple.com/DTDs/PropertyList-1.0.dtd"">
<plist version=""1.0"">
<dict>
    <key>Label</key>
    <string>{Global.AppName}-LaunchAgent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>if ! pgrep -x ""{appName}"" > /dev/null; then ""{exePath}""; fi</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
</dict>
</plist>";
    }

    #endregion macOS
}
