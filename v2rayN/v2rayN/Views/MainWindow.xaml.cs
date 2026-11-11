using System.Net;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
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
    private bool _checkingUpdates;
    private int _clientUpdatePercent;
    private int _componentUpdatePercent;
    private CancellationTokenSource? _latencyCancellation;
    private CancellationTokenSource? _updateCancellation;
    private UpdateService.VaKoLinkUpdateBatch? _preparedUpdate;
    private VaKoLinkTransport? _transport;

    public MainWindow()
    {
        InitializeComponent();
        _config = AppManager.Instance.Config;
        Title = $"VaKoLink v{InstalledClientVersion} · {RuntimeInformation.ProcessArchitecture}";

        if (AppManager.Instance.ConnectionModes is { } connection)
        {
            BindConnectionControls(connection);
        }

        ThreadPool.RegisterWaitForSingleObject(App.ProgramStarted, OnProgramStarted, null, -1, false);
        App.Current.SessionEnding += Current_SessionEnding;
        Closing += MainWindow_Closing;
        PreviewKeyDown += MainWindow_PreviewKeyDown;

        checkUpdateButton.Click += CheckUpdateButton_Click;
        clientUpdateAction.Click += ClientUpdateAction_Click;
        Loaded += (_, _) => ShowPreviousClientUpdateResult();
        IsVisibleChanged += (_, _) => ShowWhatsNewWhenVisible();
        StateChanged += (_, _) => ShowWhatsNewWhenVisible();
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
        menuDiagnostics.Click += (_, _) => ShowDiagnostics();
        menuTheme.Click += (_, _) => ShowAdvanced(themeHost, "Оформление");
        menuNodeEditor.Click += (_, _) => ShowAdvanced(nodeEditorHost, "Управление нодами");
        menuAbout.Click += (_, _) => MessageBox.Show(this, Title,
            "О программе", MessageBoxButton.OK, MessageBoxImage.Information);
        menuBackupAndRestore.Click += MenuBackupAndRestore_Click;
        backButton.Click += (_, _) =>
        {
            SetNodeEditorGroups(false);
            advancedPage.Visibility = Visibility.Collapsed;
            connectionPage.Visibility = Visibility.Visible;
        };
        nodeList.SelectionChanged += async (_, _) =>
        {
            UpdateNodeControls();
            await RefreshConfigurationSummaryAsync();
        };
        BindConfigurationControls();

        this.WhenActivated(disposables =>
        {
            AppEvents.VaKoLinkConfigurationUsageChanged.AsObservable()
                .ObserveOn(RxSchedulers.MainThreadScheduler)
                .SubscribeAsync(async _ => await RefreshConfigurationSummaryAsync())
                .DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.AddServerViaClipboardCmd, v => v.menuAddServerViaClipboard).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.AddServerViaScanCmd, v => v.menuAddServerViaScan).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.AddServerViaImageCmd, v => v.menuAddServerViaImage).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.SubSettingCmd, v => v.menuSubSetting).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.SubUpdateCmd, v => v.menuSubUpdate).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.SubUpdateCmd, v => v.updateSubscriptionsButton).DisposeWith(disposables);
            ViewModel.SubUpdateCmd.IsExecuting
                .ObserveOn(RxSchedulers.MainThreadScheduler)
                .Subscribe(updating => updateSubscriptionsButton.Content = updating ? "Обновляем…" : "Обновить")
                .DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.SubUpdateViaProxyCmd, v => v.menuSubUpdateViaProxy).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.SubGroupUpdateCmd, v => v.menuSubGroupUpdate).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.SubGroupUpdateViaProxyCmd, v => v.menuSubGroupUpdateViaProxy).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.OptionSettingCmd, v => v.menuOptionSetting).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.RoutingSettingCmd, v => v.menuRoutingSetting).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.DNSSettingCmd, v => v.menuDNSSetting).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.GlobalHotkeySettingCmd, v => v.menuGlobalHotkeySetting).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.OpenTheFileLocationCmd, v => v.menuOpenTheFileLocation).DisposeWith(disposables);

            this.OneWayBind(ViewModel, vm => vm.ProfilesViewModel.ProfileItems, v => v.nodeList.ItemsSource).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.ProfilesViewModel.SelectedProfile, v => v.nodeList.SelectedItem).DisposeWith(disposables);

            if (logHost.Content is null)
            {
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
                    _latencyCancellation?.Cancel();
                    _updateCancellation?.Cancel();
                    EndClientUpdate();
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
        _transport = transport;
        connection.BeforeCoreStop = transport.StopBeforeVpnAsync;
        connection.IsTransportRunning = () => transport.IsRunning;
        connection.RestartTransport = transport.ToggleAsync;

        void RenderTransport()
        {
            var reason = Transport104.GetUnavailableReason(connection);
            transportButton.IsEnabled = !connection.Busy && !transport.Busy && (transport.NeedsStop || reason is null);
            transportButton.Content = transport.CleanupPending ? "Завершить"
                : transport.NeedsStop ? "Остановить" : "Запустить";
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
            connectionButton.Content = connection.NeedsDisconnect && !connection.IsConnecting ? "Отключить" : "Подключить";
            connectionStatus.Text = connection.IsSwitchingNode ? "Переподключение…" : connection.Status;
            var connected = connection.IsConnected && !connection.IsSwitchingNode;
            nodeList.Tag = Tuple.Create(
                connection.IsSwitchingNode ? connection.SwitchingFromNodeId : connection.ConnectedNodeId,
                connection.IsSwitchingNode ? connection.SwitchingToNodeId : null);
            connectionNotice.Text = connection.SwitchNotice ?? string.Empty;
            connectionNotice.Visibility = connection.SwitchNotice is null ? Visibility.Collapsed : Visibility.Visible;
            connectionCard.SetResourceReference(Border.BackgroundProperty, connected ? "PultConnected" : "PultCard");
            connectionCard.SetResourceReference(Border.BorderBrushProperty, connected ? "PultConnectedOutline" : "PultOutline");
            var statusBrush = connected ? "PultGood" : connection.IsConnecting || connection.IsSwitchingNode ? "PultAccent" : "PultMuted";
            connectionIndicator.SetResourceReference(Shape.FillProperty, statusBrush);
            connectionStatus.SetResourceReference(TextBlock.ForegroundProperty, statusBrush);
            UpdateNodeControls();
            RenderTransport();
        }

        connection.Changed += () => Dispatcher.InvokeAsync(async () =>
        {
            RenderConnection();
            await RefreshConfigurationSummaryAsync();
            _ = RefreshDailyExpiryAsync();
            await TryInstallPreparedUpdateAsync(connection);
        });
        transport.Changed += () => Dispatcher.InvokeAsync(RenderTransport);
        modeProxy.Click += async (_, _) => await connection.SelectAsync(false);
        modeTun.Click += async (_, _) => await connection.SelectAsync(true);
        connectionButton.Click += async (_, _) => await ToggleConnectionAsync(connection);
        transportButton.Click += async (_, _) => await transport.ToggleAsync();
        nodeList.MouseDoubleClick += async (_, e) =>
        {
            if (e.ChangedButton == MouseButton.Left && connection is { IsConnected: true, Busy: false } && !transport.Busy &&
                e.OriginalSource is DependencyObject origin &&
                ItemsControl.ContainerFromElement(nodeList, origin) is ListBoxItem { Content: ProfileItemModel node } &&
                node.IndexId != connection.ConnectedNodeId)
            {
                e.Handled = true;
                await connection.SwitchNodeAsync(node.IndexId);
            }
        };
        RenderConnection();
    }

    private void UpdateNodeControls()
    {
        var connection = AppManager.Instance.ConnectionModes;
        var selection = nodeList.SelectedItem as ProfileItemModel;
        nodeList.Visibility = _hasNodes ? Visibility.Visible : Visibility.Collapsed;
        emptyNodes.Visibility = _hasNodes ? Visibility.Collapsed : Visibility.Visible;
        nodeList.IsEnabled = !_selectingNode && connection is { Busy: false };
        selectedNodeName.Tag = connection?.ConnectedNodeName ?? selection?.Remarks;
        selectedNodeName.ToolTip = selectedNodeName.Tag;
        measureLatencyButton.IsEnabled = _hasNodes && _latencyCancellation is null && connection is { Ready: true, Busy: false };
        checkUpdateButton.IsEnabled = !_selectingNode && !_updatingComponents && !_checkingUpdates && !_installingClient &&
            connection is { Ready: true, Busy: false };
        connectionButton.IsEnabled = !_selectingNode && !_installingClient && connection is { Ready: true, Busy: false } &&
            (connection.NeedsDisconnect || !string.IsNullOrEmpty(selection?.IndexId));
        RenderClientUpdate(connection);
    }

    private async void MeasureLatencyButton_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel?.ProfilesViewModel is not { } profiles || _latencyCancellation is not null)
        {
            return;
        }

        using var cancellation = new CancellationTokenSource();
        _latencyCancellation = cancellation;
        measureLatencyButton.Content = "Замеряем…";
        UpdateNodeControls();
        try
        {
            var nodes = await AppManager.Instance.ProfileItems(string.Empty) ?? [];
            var pending = nodes.Where(node => node.ConfigType != EConfigType.Custom &&
                (node.ConfigType.IsComplexType() || node.Port > 0)).Select(node => node.IndexId).ToHashSet();
            foreach (var row in profiles.ProfileItems)
            {
                row.DelayVal = string.Empty;
            }

            var service = new SpeedtestService(_config, async result =>
            {
                if (int.TryParse(result.Delay, out _))
                {
                    await Dispatcher.InvokeAsync(() =>
                    {
                        pending.Remove(result.IndexId);
                        return profiles.SetSpeedTestResult(result);
                    }).Task.Unwrap();
                }
            });
            await service.RunLoop(ESpeedActionType.Realping, nodes, cancellation.Token);
            if (!cancellation.IsCancellationRequested)
            {
                foreach (var id in pending)
                {
                    await profiles.SetSpeedTestResult(new() { IndexId = id, Delay = "-1" });
                }
            }
        }
        catch (Exception ex)
        {
            Logging.SaveLog("Замер задержки VaKoLink", ex);
            MainSnackbar.MessageQueue?.Enqueue("Не удалось завершить замер задержки.");
        }
        finally
        {
            _latencyCancellation = null;
            measureLatencyButton.Content = "Задержка ↻";
            UpdateNodeControls();
        }
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

    private async void AddConfigurationButton_Click(object sender, RoutedEventArgs e)
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
            _checkingUpdates || _updatingComponents || _installingClient)
        {
            return;
        }
        _checkingUpdates = true;
        _clientUpdatePercent = _componentUpdatePercent = 0;
        ShowUpdateCheckProgress("Проверка версий");
        UpdateNodeControls();
        try
        {
            var client = CheckClientUpdateAsync(connection);
            var components = CheckComponentUpdatesAsync(connection);
            await Task.WhenAll(client, components);

            var results = await InstallPreparedComponentsAsync(connection) ?? await components;
            ShowUpdateReport(await client, results, connection.NeedsDisconnect);
        }
        finally
        {
            _checkingUpdates = false;
            updateProgressPanel.Visibility = Visibility.Collapsed;
            UpdateNodeControls();
        }
        await TryInstallPreparedUpdateAsync(connection);
    }

    private async Task<IReadOnlyList<string>> CheckComponentUpdatesAsync(VaKoLinkConnection connection)
    {
        if (_preparedUpdate is { } existing)
        {
            _componentUpdatePercent = 100;
            ShowUpdateCheckProgress("Компоненты проверены");
            return existing.Preview;
        }

        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(connection.ConnectedSessionToken);
        _updateCancellation = cancellation;
        var updateViaProxy = _config.CheckUpdateItem.UpdateViaProxy;
        var proxy = updateViaProxy && connection.ConnectedProxyPort is { } port
            ? new WebProxy($"socks5://{Global.Loopback}:{port}")
            : null;
        var viaTun = connection.IsConnected && connection.UseTun;
        var progress = new Progress<(int Percent, string Stage)>(value =>
        {
            if (_updateCancellation == cancellation && value.Percent >= _componentUpdatePercent)
            {
                _componentUpdatePercent = value.Percent;
                ShowUpdateCheckProgress(value.Stage);
            }
        });

        try
        {
            var service = new UpdateService(_config, (_, _) => Task.CompletedTask);
            var batch = await service.PrepareVaKoLinkUpdatesAsync(proxy, useSystemProxy: updateViaProxy && !connection.IsConnected,
                progress, cancellation.Token, viaTun);
            if (batch.HasChanges)
            {
                _preparedUpdate = batch;
                return batch.Preview;
            }
            using (batch)
            {
                return batch.Preview;
            }
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            return ComponentCheckError("проверка прервана. Запустите её снова.");
        }
        catch (Exception ex)
        {
            Logging.SaveLog("Обновление компонентов VaKoLink", ex);
            return ComponentCheckError($"ошибка проверки. {ex.Message}");
        }
        finally
        {
            _updateCancellation = null;
            _componentUpdatePercent = 100;
            ShowUpdateCheckProgress("Компоненты проверены");
        }
    }

    private static IReadOnlyList<string> ComponentCheckError(string reason) =>
        [$"Xray — {reason}", $"mihomo — {reason}", $"sing-box — {reason}", $"geoFiles — {reason}"];

    private async Task<IReadOnlyList<string>?> InstallPreparedComponentsAsync(VaKoLinkConnection connection)
    {
        if (_preparedUpdate is null || connection.NeedsDisconnect || connection.Busy)
        {
            return null;
        }

        _updatingComponents = true;
        UpdateNodeControls();
        try
        {
            IReadOnlyList<string>? results = null;
            await connection.RunWhileDisconnectedAsync(async () => results = await InstallPendingComponentsAsync());
            return results;
        }
        finally
        {
            _updatingComponents = false;
            UpdateNodeControls();
        }
    }

    private async Task<IReadOnlyList<string>> InstallPendingComponentsAsync()
    {
        if (_preparedUpdate is not { } batch)
        {
            return [];
        }
        _preparedUpdate = null;
        using (batch)
        {
            ShowUpdateProgress(100, "Установка компонентов");
            return await batch.InstallAsync();
        }
    }

    private async Task TryInstallPreparedUpdateAsync(VaKoLinkConnection connection)
    {
        if (_checkingUpdates || _updatingComponents || _installingClient)
        {
            return;
        }
        try
        {
            if (await InstallPreparedComponentsAsync(connection) is { } results)
            {
                Logging.SaveLog(string.Join(Environment.NewLine, results));
                MainSnackbar.MessageQueue?.Enqueue("Установка компонентов завершена. Результаты в журнале.");
            }
        }
        finally
        {
            if (!_checkingUpdates && !_installingClient)
            {
                updateProgressPanel.Visibility = Visibility.Collapsed;
            }
        }
    }

    private void ShowUpdateCheckProgress(string stage) =>
        ShowUpdateProgress((_clientUpdatePercent + _componentUpdatePercent) / 2, stage);

    private void ShowUpdateProgress(int percent, string stage)
    {
        updateProgressPanel.Visibility = Visibility.Visible;
        updatePercent.Text = $"{percent}%";
        updateStage.Text = stage;
    }

    private void ShowUpdateReport(string clientStatus, IReadOnlyList<string> components, bool needsDisconnect)
    {
        var notice = needsDisconnect && _preparedUpdate is { HasChanges: true }
            ? "Скачанные компоненты установятся после отключения VPN."
            : null;
        var report = string.Join(Environment.NewLine, new[] { $"VaKoLink — {clientStatus}" }.Concat(components));
        if (notice is not null)
        {
            report += $"{Environment.NewLine}{Environment.NewLine}{notice}";
        }
        Logging.SaveLog(report);
        if (IsVisible)
        {
            new UpdateReportWindow(clientStatus, components, notice) { Owner = this }.ShowDialog();
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
        if (content == nodeEditorHost && nodeEditorHost.Content is null)
        {
            ViewHost.Show(nodeEditorHost, ViewModel.ProfilesViewModel);
        }
        SetNodeEditorGroups(content == nodeEditorHost);
        advancedTitle.Text = title;
        logHost.Visibility = content == logHost ? Visibility.Visible : Visibility.Collapsed;
        themeHost.Visibility = content == themeHost ? Visibility.Visible : Visibility.Collapsed;
        nodeEditorHost.Visibility = content == nodeEditorHost ? Visibility.Visible : Visibility.Collapsed;
        connectionPage.Visibility = Visibility.Collapsed;
        advancedPage.Visibility = Visibility.Visible;
    }

    private void SetNodeEditorGroups(bool show)
    {
        var profiles = ViewModel.ProfilesViewModel;
        if (profiles.ShowNodeEditorGroups != show)
        {
            profiles.ShowNodeEditorGroups = show;
            _ = profiles.RefreshServers();
        }
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
