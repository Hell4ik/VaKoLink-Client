using v2rayN.Manager;
using v2rayN.ViewModels;
using v2rayN.Views;
using VaKoLink.Updates;

namespace v2rayN;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App
{
    public static EventWaitHandle ProgramStarted;

    public App()
    {
        DispatcherUnhandledException += App_DispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
        TaskScheduler.UnobservedTaskException += TaskScheduler_UnobservedTaskException;
    }

    /// <summary>
    /// Open only one process
    /// </summary>
    /// <param name="e"></param>
    protected override void OnStartup(StartupEventArgs e)
    {
        AppManager.Instance.UseVaKoLinkProfile = true;
        var exePathKey = Utils.GetMd5("VaKoLink:" + Utils.GetBaseDirectory().ToUpperInvariant());

        var rebootas = e.Args.Any(t => t == Global.RebootAs);
        if (!rebootas && EventWaitHandle.TryOpenExisting(
                Utils.GetMd5(Utils.GetBaseDirectory("v2rayN.exe")), out var legacyInstance))
        {
            using (legacyInstance)
            {
                legacyInstance.Set();
            }
            Environment.Exit(0);
            return;
        }
        ProgramStarted = new EventWaitHandle(false, EventResetMode.AutoReset, exePathKey, out var bCreatedNew);
        if (!rebootas && !bCreatedNew)
        {
            ProgramStarted.Set();
            Environment.Exit(0);
            return;
        }

        try
        {
            if (!ClientUpdateProcess.CanStart())
            {
                Environment.Exit(0);
                return;
            }
        }
        catch (Exception ex)
        {
            UI.Show($"Не удалось открыть VaKoLink во время обновления. {ex.Message}");
            Environment.Exit(1);
            return;
        }

        if (!AppManager.Instance.InitApp())
        {
            UI.Show($"Loading GUI configuration file is abnormal,please restart the application{Environment.NewLine}加载GUI配置文件异常,请重启应用");
            Environment.Exit(0);
            return;
        }

        AppManager.Instance.WindowDialog = new WindowDialog();
        VaKoLinkResumeState? updateResume = null;
        try
        {
            updateResume = ClientUpdateProcess.TakeResume(e.Args);
        }
        catch (Exception ex)
        {
            Logging.SaveLog("Восстановление подключения после обновления VaKoLink", ex);
            UI.Show("Не удалось прочитать сохранённое подключение после обновления.");
        }
        AppManager.Instance.ConnectionModes = new(AppManager.Instance.Config,
            e.Args.Contains(Global.VaKoLinkLogonArgument), updateResume);

        AppManager.Instance.InitComponents();

        RxAppBuilder.CreateReactiveUIBuilder()
            .WithWpf()
            .BuildApp();

        base.OnStartup(e);

        var themeSettings = new ThemeSettingViewModel();
        var mainWindowViewModel = new MainWindowViewModel();
        var viewFor = SimpleViewLocator.Instance.ResolveView(mainWindowViewModel);
        viewFor!.ViewModel = mainWindowViewModel;

        var mainWindow = (MainWindow)viewFor;
        mainWindow.ThemeSettings = themeSettings;
        MainWindow = mainWindow;
        WindowsUtils.SetDarkBorder(mainWindow, AppManager.Instance.Config.UiItem.CurrentTheme);
        mainWindow.Show();
        AutoStartupHandler.EnsureVaKoLinkLogonTask(AppManager.Instance.Config);
    }

    private void App_DispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Logging.SaveLog("App_DispatcherUnhandledException", e.Exception);
        e.Handled = true;
    }

    private void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject != null)
        {
            Logging.SaveLog("CurrentDomain_UnhandledException", (Exception)e.ExceptionObject);
        }
    }

    private void TaskScheduler_UnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        Logging.SaveLog("TaskScheduler_UnobservedTaskException", e.Exception);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        Logging.SaveLog("OnExit");
        base.OnExit(e);
        Process.GetCurrentProcess().Kill();
    }
}
