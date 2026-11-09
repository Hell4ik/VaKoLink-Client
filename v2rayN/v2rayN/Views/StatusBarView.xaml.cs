using System.Windows.Media.Imaging;
using System.Windows.Media;
using v2rayN.Manager;

namespace v2rayN.Views;

public partial class StatusBarView
{
    private static Config _config;
    private string? _vaKoLinkTrayStatus;

    public StatusBarView()
    {
        InitializeComponent();
        _config = AppManager.Instance.Config;
        if (AppManager.Instance.ConnectionModes is not null)
        {
            statusDetails.Visibility = Visibility.Collapsed;
            spEnableTun.Visibility = cmbSystemProxy.Visibility = Visibility.Collapsed;
            menuSystemProxyClear.Visibility = menuSystemProxySet.Visibility =
                menuSystemProxyNothing.Visibility = menuSystemProxyPac.Visibility = Visibility.Collapsed;
        }

        menuExit.Click += menuExit_Click;
        txtRunningServerDisplay.PreviewMouseDown += txtRunningInfoDisplay_MouseDoubleClick;
        txtRunningInfoDisplay.PreviewMouseDown += txtRunningInfoDisplay_MouseDoubleClick;

        this.WhenActivated(disposables =>
        {
            AppEvents.AppExitRequested.AsObservable()
                .ObserveOn(RxSchedulers.MainThreadScheduler)
                .Subscribe(_ => tbNotify.Dispose()).DisposeWith(disposables);

            //system proxy
            this.OneWayBind(ViewModel, vm => vm.BlSystemProxyClear, v => v.menuSystemProxyClear2.Visibility, conversionHint: BooleanToVisibilityHint.UseHidden, viewModelToViewConverterOverride: new BooleanToVisibilityTypeConverter()).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.BlSystemProxySet, v => v.menuSystemProxySet2.Visibility, conversionHint: BooleanToVisibilityHint.UseHidden, viewModelToViewConverterOverride: new BooleanToVisibilityTypeConverter()).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.BlSystemProxyNothing, v => v.menuSystemProxyNothing2.Visibility, conversionHint: BooleanToVisibilityHint.UseHidden, viewModelToViewConverterOverride: new BooleanToVisibilityTypeConverter()).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.BlSystemProxyPac, v => v.menuSystemProxyPac2.Visibility, conversionHint: BooleanToVisibilityHint.UseHidden, viewModelToViewConverterOverride: new BooleanToVisibilityTypeConverter()).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.SystemProxyClearCmd, v => v.menuSystemProxyClear).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.SystemProxySetCmd, v => v.menuSystemProxySet).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.SystemProxyNothingCmd, v => v.menuSystemProxyNothing).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.SystemProxyPacCmd, v => v.menuSystemProxyPac).DisposeWith(disposables);

            //routings and servers
            this.OneWayBind(ViewModel, vm => vm.RoutingItems, v => v.cmbRoutings.ItemsSource).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.SelectedRouting, v => v.cmbRoutings.SelectedItem).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.BlRouting, v => v.menuRoutings.Visibility).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.BlRouting, v => v.sepRoutings.Visibility).DisposeWith(disposables);

            this.OneWayBind(ViewModel, vm => vm.Servers, v => v.cmbServers.ItemsSource).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.SelectedServer, v => v.cmbServers.SelectedItem).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.BlServers, v => v.cmbServers.Visibility).DisposeWith(disposables);

            //tray menu
            this.BindCommand(ViewModel, vm => vm.AddServerViaClipboardCmd, v => v.menuAddServerViaClipboard2).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.AddServerViaScanCmd, v => v.menuAddServerViaScan2).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.SubUpdateCmd, v => v.menuSubUpdate2).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.SubUpdateViaProxyCmd, v => v.menuSubUpdateViaProxy2).DisposeWith(disposables);

            this.BindCommand(ViewModel, vm => vm.CopyProxyCmdToClipboardCmd, v => v.menuCopyProxyCmdToClipboard).DisposeWith(disposables);

            if (AppManager.Instance.ConnectionModes is null)
            {
                this.OneWayBind(ViewModel, vm => vm.RunningServerToolTipText, v => v.tbNotify.ToolTipText).DisposeWith(disposables);
            }
            this.OneWayBind(ViewModel, vm => vm.NotifyLeftClickCmd, v => v.tbNotify.LeftClickCommand).DisposeWith(disposables);

            //status bar
            this.OneWayBind(ViewModel, vm => vm.InboundDisplay, v => v.txtInboundDisplay.Text).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.InboundLanDisplay, v => v.txtInboundLanDisplay.Text).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.RunningServerDisplay, v => v.txtRunningServerDisplay.Text).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.RunningInfoDisplay, v => v.txtRunningInfoDisplay.Text).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.SpeedProxyDisplay, v => v.txtSpeedProxyDisplay.Text).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.SpeedDirectDisplay, v => v.txtSpeedDirectDisplay.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.EnableTun, v => v.togEnableTun.IsChecked).DisposeWith(disposables);

            this.Bind(ViewModel, vm => vm.SystemProxySelected, v => v.cmbSystemProxy.SelectedIndex).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.RoutingItems, v => v.cmbRoutings2.ItemsSource).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.SelectedRouting, v => v.cmbRoutings2.SelectedItem).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.BlRouting, v => v.cmbRoutings2.Visibility).DisposeWith(disposables);

            ViewModel.SetClipboardDataInteraction.RegisterHandler(interaction =>
            {
                var strData = interaction.Input;
                WindowsUtils.SetClipboardData(strData);
                interaction.SetOutput(RxVoid.Default);
            }).DisposeWith(disposables);

            ViewModel.DispatcherRefreshIconInteraction.RegisterHandler(interaction =>
            {
                Application.Current?.Dispatcher.Invoke(async () => await RefreshIcon(), DispatcherPriority.Normal);
                interaction.SetOutput(RxVoid.Default);
            }).DisposeWith(disposables);
        });

        if (AppManager.Instance.ConnectionModes is null)
        {
            _ = RefreshIcon();
        }
        else
        {
            SetVaKoLinkTrayState(connected: false, useTun: false, transportRunning: false);
        }
    }

    private async Task RefreshIcon()
    {
        if (AppManager.Instance.ConnectionModes is not null)
        {
            return;
        }
        tbNotify.Icon = await WindowsManager.Instance.GetNotifyIcon(_config);
        Application.Current.MainWindow?.Icon = WindowsManager.Instance.GetAppIcon(_config);
    }

    internal void SetVaKoLinkTrayState(bool connected, bool useTun, bool transportRunning)
    {
        var (badge, status) = (connected, useTun, transportRunning) switch
        {
            (_, _, true) => (Brushes.MediumPurple, "Proxy + Transport"),
            (true, true, _) => (Brushes.Tomato, "TUN подключён"),
            (true, false, _) => (Brushes.LimeGreen, "Proxy подключён"),
            _ => (null, "Отключено")
        };
        if (_vaKoLinkTrayStatus == status)
        {
            return;
        }

        var icon = BitmapFrame.Create(new Uri("pack://application:,,,/VaKoLink;component/Resources/VaKoLinkTray.ico"));
        if (badge is null)
        {
            tbNotify.IconSource = icon;
        }
        else
        {
            var visual = new DrawingVisual();
            using (var drawing = visual.RenderOpen())
            {
                drawing.DrawImage(icon, new Rect(0, 0, 32, 32));
                drawing.DrawEllipse(badge, new Pen(Brushes.Black, 1.5), new Point(25, 25), 6, 6);
            }
            var rendered = new RenderTargetBitmap(32, 32, 96, 96, PixelFormats.Pbgra32);
            rendered.Render(visual);
            tbNotify.IconSource = rendered;
        }
        tbNotify.ToolTipText = $"VaKoLink — {status}";
        _vaKoLinkTrayStatus = status;
    }

    private async void menuExit_Click(object sender, RoutedEventArgs e)
    {
        await AppManager.Instance.AppExitAsync(true);
    }

    private void txtRunningInfoDisplay_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        ViewModel?.TestServerAvailability();
    }
}
