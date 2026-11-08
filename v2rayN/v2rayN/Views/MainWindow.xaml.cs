using System.Net;
using System.Reflection;
using System.Windows.Controls;
using System.Windows.Media;
using MaterialDesignThemes.Wpf;
using ServiceLib.Services;
using v2rayN.Base;
using v2rayN.Manager;
using v2rayN.ViewModels;

namespace v2rayN.Views;

public partial class MainWindow
{
    private readonly Config _config;
    internal ThemeSettingViewModel ThemeSettings { get; set; } = null!;
    private BackupAndRestoreView? _backupAndRestoreView;
    private bool _hasNodes;
    private bool _selectingNode;
    private bool _updatingComponents;
    private CancellationTokenSource? _updateCancellation;
    private UpdateService.VaKoLinkUpdateBatch? _preparedUpdate;

    public MainWindow()
    {
        InitializeComponent();
        _config = AppManager.Instance.Config;
        var revision = typeof(MainWindow).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .Single(metadata => metadata.Key == "VaKoLinkRevision").Value;
        Title = $"VaKoLink - V{Utils.GetVersionInfo()} (VaKoLink r{revision}) - {RuntimeInformation.ProcessArchitecture}";

        if (AppManager.Instance.ConnectionModes is { } connection)
        {
            BindConnectionControls(connection);
        }

        ThreadPool.RegisterWaitForSingleObject(App.ProgramStarted, OnProgramStarted, null, -1, false);
        App.Current.SessionEnding += Current_SessionEnding;
        Closing += MainWindow_Closing;
        PreviewKeyDown += MainWindow_PreviewKeyDown;

        checkUpdateButton.Click += CheckUpdateButton_Click;
        menuUpdateViaProxy.IsChecked = _config.CheckUpdateItem.UpdateViaProxy;
        menuUpdateViaProxy.Click += async (_, _) =>
        {
            menuUpdateViaProxy.IsEnabled = false;
            var previous = _config.CheckUpdateItem.UpdateViaProxy;
            _config.CheckUpdateItem.UpdateViaProxy = menuUpdateViaProxy.IsChecked;
            if (await ConfigHandler.SaveConfig(_config) != 0)
            {
                _config.CheckUpdateItem.UpdateViaProxy = previous;
                menuUpdateViaProxy.IsChecked = previous;
                MainSnackbar.MessageQueue?.Enqueue("Не удалось сохранить настройку обновлений.");
            }
            menuUpdateViaProxy.IsEnabled = true;
        };
        menuLog.Click += (_, _) => ShowAdvanced(logHost, "Журнал");
        menuTheme.Click += (_, _) => ShowAdvanced(themeHost, "Оформление");
        menuAbout.Click += (_, _) => MessageBox.Show(this, Title,
            "О программе", MessageBoxButton.OK, MessageBoxImage.Information);
        menuBackupAndRestore.Click += MenuBackupAndRestore_Click;
        backButton.Click += (_, _) =>
        {
            advancedPage.Visibility = Visibility.Collapsed;
            connectionPage.Visibility = Visibility.Visible;
        };

        this.WhenActivated(disposables =>
        {
            this.BindCommand(ViewModel, vm => vm.AddServerViaClipboardCmd, v => v.menuAddServerViaClipboard).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.AddServerViaScanCmd, v => v.menuAddServerViaScan).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.AddServerViaImageCmd, v => v.menuAddServerViaImage).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.SubSettingCmd, v => v.menuSubSetting).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.SubUpdateCmd, v => v.menuSubUpdate).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.SubUpdateViaProxyCmd, v => v.menuSubUpdateViaProxy).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.SubGroupUpdateCmd, v => v.menuSubGroupUpdate).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.SubGroupUpdateViaProxyCmd, v => v.menuSubGroupUpdateViaProxy).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.OptionSettingCmd, v => v.menuOptionSetting).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.RoutingSettingCmd, v => v.menuRoutingSetting).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.DNSSettingCmd, v => v.menuDNSSetting).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.GlobalHotkeySettingCmd, v => v.menuGlobalHotkeySetting).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.OpenTheFileLocationCmd, v => v.menuOpenTheFileLocation).DisposeWith(disposables);

            if (profilesHost.Content is null)
            {
                ViewHost.Show(profilesHost, ViewModel.ProfilesViewModel);
                ViewHost.Show(logHost, ViewModel.MsgViewModel);
                ViewHost.Show(contentStatusBarView, ViewModel.StatusBarViewModel);
            }

            this.WhenAnyValue(v => v.ViewModel.HasConnectionServers)
                .ObserveOn(RxSchedulers.MainThreadScheduler)
                .Subscribe(hasNodes =>
                {
                    _hasNodes = hasNodes;
                    UpdateNodeControls();
                })
                .DisposeWith(disposables);

            ViewModel.ReadTextFromClipboardInteraction.RegisterHandler(interaction =>
            {
                interaction.SetOutput(WindowsUtils.GetClipboardData());
            }).DisposeWith(disposables);

            ViewModel.ScanScreenInteraction.RegisterHandler(interaction =>
            {
                interaction.SetOutput(CaptureQrScreen());
            }).DisposeWith(disposables);

            ViewModel.BrowseImageFileInteraction.RegisterHandler(interaction =>
            {
                var selected = UI.OpenFileDialog(out var fileName, "Изображения|*.png;*.jpg;*.jpeg;*.bmp|Все файлы|*.*");
                interaction.SetOutput(selected == true ? fileName : null);
            }).DisposeWith(disposables);

            ViewModel.ShowHideWindowInteraction.RegisterHandler(interaction =>
            {
                ShowHideWindow(interaction.Input);
                interaction.SetOutput(RxVoid.Default);
            }).DisposeWith(disposables);

            AppEvents.SendSnackMsgRequested.AsObservable()
                .ObserveOn(RxSchedulers.MainThreadScheduler)
                .Subscribe(content => MainSnackbar.MessageQueue?.Enqueue(content))
                .DisposeWith(disposables);

            AppEvents.AppExitRequested.AsObservable()
                .ObserveOn(RxSchedulers.MainThreadScheduler)
                .Subscribe(_ =>
                {
                    _updateCancellation?.Cancel();
                    _preparedUpdate?.Dispose();
                    _preparedUpdate = null;
                    StorageUI();
                })
                .DisposeWith(disposables);

            AppEvents.ShutdownRequested.AsObservable()
                .ObserveOn(RxSchedulers.MainThreadScheduler)
                .Subscribe(_ => Application.Current.Shutdown())
                .DisposeWith(disposables);
        });

        if (_config.UiItem.AutoHideStartup)
        {
            WindowState = WindowState.Minimized;
        }
        if (!_config.GuiItem.EnableHWA)
        {
            RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
        }
        WindowsManager.Instance.RegisterGlobalHotkey(_config, OnHotkeyHandler, null);
    }

    private void BindConnectionControls(VaKoLinkConnection connection)
    {
        var transport = new VaKoLinkTransport(() => Transport104.PrepareAsync(connection));
        connection.BeforeCoreStop = transport.StopBeforeVpnAsync;

        void RenderTransport()
        {
            var reason = Transport104.GetUnavailableReason(connection);
            transportButton.IsEnabled = !transport.Busy && (transport.NeedsStop || reason is null);
            transportButton.Content = transport.CleanupPending ? "Завершить остановку Transport"
                : transport.NeedsStop ? "Остановить Transport" : "Запустить Transport";
            transportStatus.Text = !transport.Busy && !transport.NeedsStop && reason is not null
                ? reason
                : transport.Status;
            if (contentStatusBarView.Content is StatusBarView tray)
            {
                tray.SetVaKoLinkTrayState(connection.IsConnected, connection.UseTun, transport.IsRunning);
            }
        }

        void RenderConnection()
        {
            modeProxy.IsChecked = !connection.UseTun;
            modeTun.IsChecked = connection.UseTun;
            modeProxy.IsEnabled = modeTun.IsEnabled = connection.Ready && !connection.Busy;
            connectionButton.Content = connection.NeedsDisconnect ? "Отключить" : "Подключить";
            connectionStatus.Text = connection.Status;
            UpdateNodeControls();
            RenderTransport();
        }

        connection.Changed += () => Dispatcher.InvokeAsync(async () =>
        {
            RenderConnection();
            await TryInstallPreparedUpdateAsync(connection);
        });
        transport.Changed += () => Dispatcher.InvokeAsync(RenderTransport);
        modeProxy.Click += async (_, _) => await connection.SelectAsync(false);
        modeTun.Click += async (_, _) => await connection.SelectAsync(true);
        connectionButton.Click += async (_, _) => await ToggleConnectionAsync(connection);
        transportButton.Click += async (_, _) => await transport.ToggleAsync();
        RenderConnection();
    }

    private void UpdateNodeControls()
    {
        var connection = AppManager.Instance.ConnectionModes;
        profilesHost.Visibility = _hasNodes ? Visibility.Visible : Visibility.Collapsed;
        emptyNodes.Visibility = _hasNodes ? Visibility.Collapsed : Visibility.Visible;
        profilesHost.IsEnabled = !_selectingNode && connection?.Busy != true;
        checkUpdateButton.IsEnabled = !_selectingNode && !_updatingComponents && _preparedUpdate is null &&
            connection is { Ready: true, Busy: false };
        connectionButton.IsEnabled = !_selectingNode && connection is { Ready: true, Busy: false } &&
            (connection.NeedsDisconnect || _hasNodes);
    }

    private async Task ToggleConnectionAsync(VaKoLinkConnection connection)
    {
        if (!connection.NeedsDisconnect && ViewModel?.ProfilesViewModel is { SelectedProfile.IndexId: { } indexId } profiles &&
            indexId != _config.IndexId)
        {
            _selectingNode = true;
            UpdateNodeControls();
            try
            {
                await profiles.SetDefaultServer(indexId, reload: false);
                if (_config.IndexId != indexId)
                {
                    MainSnackbar.MessageQueue?.Enqueue("Не удалось выбрать ноду.");
                    return;
                }
                await connection.ToggleAsync();
            }
            finally
            {
                _selectingNode = false;
                UpdateNodeControls();
            }
            return;
        }
        await connection.ToggleAsync();
    }

    private async void AddSubscriptionButton_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } viewModel)
        {
            return;
        }

        var choices = (DataTemplate)Resources["SubscriptionImportChoices"];
        var choice = await DialogHost.Show(choices.LoadContent(), "RootDialog");
        if (choice is "Qr")
        {
            var qrChoices = (DataTemplate)Resources["SubscriptionQrChoices"];
            choice = await DialogHost.Show(qrChoices.LoadContent(), "RootDialog");
        }

        switch (choice)
        {
            case "Clipboard":
                await viewModel.AddServerViaClipboardAsync(null);
                break;
            case "Screen":
                await viewModel.AddServerViaScanAsync();
                break;
            case "File":
                await viewModel.AddServerViaImageAsync();
                break;
            case "Manual":
                await viewModel.ProfilesViewModel.AddSubCmd.Execute().ToTask();
                break;
        }
    }

    private async void CheckUpdateButton_Click(object sender, RoutedEventArgs e)
    {
        if (AppManager.Instance.ConnectionModes is not { Ready: true, Busy: false } connection ||
            _updatingComponents || _preparedUpdate is not null)
        {
            return;
        }

        _updatingComponents = true;
        UpdateNodeControls();
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(connection.ConnectedSessionToken);
        _updateCancellation = cancellation;
        var updateViaProxy = _config.CheckUpdateItem.UpdateViaProxy;
        var proxy = updateViaProxy && connection.ConnectedProxyPort is { } port
            ? new WebProxy($"socks5://{Global.Loopback}:{port}")
            : null;
        var viaTun = connection.IsConnected && connection.UseTun;
        var preparing = true;
        var displayedPercent = 0;
        var progress = new Progress<(int Percent, string Stage)>(value =>
        {
            if (preparing && value.Percent >= displayedPercent)
            {
                displayedPercent = value.Percent;
                ShowUpdateProgress(value.Percent, value.Stage);
            }
        });

        ShowUpdateProgress(0, "Проверка версий");
        try
        {
            var service = new UpdateService(_config, (_, _) => Task.CompletedTask);
            var batch = await service.PrepareVaKoLinkUpdatesAsync(proxy, useSystemProxy: updateViaProxy && !connection.IsConnected,
                progress, cancellation.Token, viaTun);
            preparing = false;
            if (!batch.HasChanges)
            {
                using (batch)
                {
                    ShowUpdateProgress(100, "Проверка завершена");
                    ShowUpdateReport(batch.Preview);
                }
            }
            else
            {
                _preparedUpdate = batch;
                if (connection.NeedsDisconnect)
                {
                    ShowUpdateProgress(100, "Ожидание отключения VPN");
                    ShowUpdateReport([.. batch.Preview, "", "Скачанные обновления установятся после отключения VPN."]);
                }
            }
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            MainSnackbar.MessageQueue?.Enqueue("Соединение изменилось. Запустите проверку обновлений снова.");
        }
        catch (Exception ex)
        {
            Logging.SaveLog("Обновление компонентов VaKoLink", ex);
            ShowUpdateReport([$"Ошибка обновления. {ex.Message}"]);
        }
        finally
        {
            preparing = false;
            _updateCancellation = null;
            _updatingComponents = false;
            if (_preparedUpdate is null)
            {
                updateProgressPanel.Visibility = Visibility.Collapsed;
            }
            UpdateNodeControls();
        }

        await TryInstallPreparedUpdateAsync(connection);
    }

    private async Task TryInstallPreparedUpdateAsync(VaKoLinkConnection connection)
    {
        if (_updatingComponents || _preparedUpdate is not { } batch || connection.NeedsDisconnect || connection.Busy)
        {
            return;
        }

        _updatingComponents = true;
        UpdateNodeControls();
        try
        {
            IReadOnlyList<string>? results = null;
            await connection.RunWhileDisconnectedAsync(async () =>
            {
                _preparedUpdate = null;
                using (batch)
                {
                    ShowUpdateProgress(100, "Установка обновлений");
                    results = await batch.InstallAsync();
                }
            });
            if (results is not null)
            {
                ShowUpdateReport(results);
            }
        }
        catch (Exception ex)
        {
            Logging.SaveLog("Установка компонентов VaKoLink", ex);
            ShowUpdateReport([$"Ошибка установки. {ex.Message}"]);
        }
        finally
        {
            _updatingComponents = false;
            if (_preparedUpdate is null)
            {
                updateProgressPanel.Visibility = Visibility.Collapsed;
            }
            UpdateNodeControls();
        }
    }

    private void ShowUpdateProgress(int percent, string stage)
    {
        updateProgressPanel.Visibility = Visibility.Visible;
        updatePercent.Text = $"{percent}%";
        updateStage.Text = stage;
    }

    private void ShowUpdateReport(IReadOnlyList<string> results)
    {
        var report = string.Join(Environment.NewLine, results);
        Logging.SaveLog(report);
        if (IsVisible)
        {
            MessageBox.Show(this, report, "Обновления компонентов", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else
        {
            MainSnackbar.MessageQueue?.Enqueue(report);
        }
    }

    private void ShowAdvanced(ContentControl content, string title)
    {
        if (content == themeHost)
        {
            themeHost.Content ??= new ThemeSettingView(ThemeSettings);
        }
        advancedTitle.Text = title;
        logHost.Visibility = content == logHost ? Visibility.Visible : Visibility.Collapsed;
        themeHost.Visibility = content == themeHost ? Visibility.Visible : Visibility.Collapsed;
        connectionPage.Visibility = Visibility.Collapsed;
        advancedPage.Visibility = Visibility.Visible;
    }

    private void OnProgramStarted(object state, bool timeout)
    {
        Application.Current?.Dispatcher.Invoke(() => ShowHideWindow(true));
    }

    private void OnHotkeyHandler(EGlobalHotkey key)
    {
        if (key == EGlobalHotkey.ShowForm)
        {
            ShowHideWindow(null);
        }
    }

    private void MainWindow_Closing(object? sender, CancelEventArgs e)
    {
        e.Cancel = true;
        StorageUI();
        ShowHideWindow(false);
    }

    private async void Current_SessionEnding(object sender, SessionEndingCancelEventArgs e)
    {
        Logging.SaveLog("Current_SessionEnding");
        StorageUI();
        await AppManager.Instance.AppExitAsync(false);
    }

    private async void MainWindow_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (ViewModel is not { } viewModel || Keyboard.Modifiers != ModifierKeys.Control)
        {
            return;
        }

        if (e.Key == Key.V && Keyboard.FocusedElement is not TextBox)
        {
            e.Handled = true;
            var clipboardData = WindowsUtils.GetClipboardData();
            if (clipboardData.IsNotEmpty())
            {
                await viewModel.AddServerViaClipboardAsync(clipboardData);
            }
        }
        else if (e.Key == Key.S)
        {
            e.Handled = true;
            await viewModel.ScanScreenResult(CaptureQrScreen());
        }
    }

    private byte[]? CaptureQrScreen()
    {
        ShowHideWindow(false);
        try
        {
            return QRCodeWindowsUtils.CaptureScreen(this);
        }
        finally
        {
            ShowHideWindow(true);
        }
    }

    private void MenuBackupAndRestore_Click(object sender, RoutedEventArgs e)
    {
        _backupAndRestoreView ??= new BackupAndRestoreView();
        _backupAndRestoreView.ViewModel = ViewModel?.BackupAndRestoreViewModel;
        DialogHost.Show(_backupAndRestoreView, "RootDialog");
    }

    public void ShowHideWindow(bool? show)
    {
        var visible = show ?? !AppManager.Instance.ShowInTaskbar;
        if (visible)
        {
            Show();
            if (WindowState == WindowState.Minimized)
            {
                WindowState = WindowState.Normal;
            }
            Activate();
            Focus();
        }
        else
        {
            Hide();
        }
        AppManager.Instance.ShowInTaskbar = visible;
    }

    protected override void OnLoaded(object? sender, RoutedEventArgs e)
    {
        base.OnLoaded(sender, e);
        if (_config.UiItem.AutoHideStartup)
        {
            ShowHideWindow(false);
        }
    }

    private void StorageUI() => ConfigHandler.SaveWindowSizeItem(_config, GetType().Name, Width, Height);
}
