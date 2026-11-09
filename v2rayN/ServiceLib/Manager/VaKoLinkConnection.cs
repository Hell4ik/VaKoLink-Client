namespace ServiceLib.Manager;

[SupportedOSPlatform("windows")]
public sealed class VaKoLinkConnection(Config config, bool launchedAtLogon = false)
{
    private readonly SemaphoreSlim _transition = new(1, 1);
    private readonly string _tunName = $"VaKoLink-{Utils.GetMd5(Utils.StartupPath())[..8]}";
    private ProxySettingWindows.TemporaryProxy? _proxy;
    private bool _ownsCore;
    private bool _ownsTun;
    private bool _requiresPreCore;
    private bool _closing;
    private bool _connected;
    private ProfileItem? _connectedProfile;
    private bool _restartingTransport;
    private CancellationTokenSource? _monitor;

    public event Action? Changed;
    public bool Ready { get; private set; }
    public bool Busy { get; private set; }
    public bool IsConnecting { get; private set; }
    public bool IsSwitchingNode { get; private set; }
    public bool UseTun => config.VaKoLinkUseTun;
    public bool IsConnected => _connected;
    public string? ConnectedNodeId => _connectedProfile?.IndexId;
    public string? ConnectedNodeName => _connectedProfile?.Remarks;
    public int? ConnectedProxyPort { get; private set; }
    public CancellationToken ConnectedSessionToken { get; private set; }
    public bool IsProxyReady => _connected && !UseTun && (!Busy || _restartingTransport) && !_closing;
    public Func<Task>? BeforeCoreStop { get; set; }
    public Func<bool>? IsTransportRunning { get; set; }
    public Func<Task>? RestartTransport { get; set; }
    public bool NeedsDisconnect => _ownsCore || _proxy is not null;
    public string Status { get; private set; } = "Отключено";

    public async Task MarkReadyAsync()
    {
        var action = "обработать снимок системного прокси";
        try
        {
            ProxySettingWindows.TemporaryProxy.RecoverOnStartup();
            action = "добавить встроенные правила VaKoLink";
            await VaKoLinkRouting.EnsureInstalledAsync();
            Ready = true;
            if (launchedAtLogon && config.GuiItem.AutoRun && config.VaKoLinkResume is { } resume)
            {
                await TransitionAsync(async () =>
                {
                    var profile = await AppManager.Instance.GetProfileItem(resume.NodeId);
                    if (profile is null)
                    {
                        Status = $"Нода «{resume.NodeName}» больше недоступна. Выберите другую ноду.";
                        return;
                    }
                    config.VaKoLinkUseTun = resume.UseTun;
                    await StartAsync(profile);
                });
                return;
            }
        }
        catch (Exception ex)
        {
            Logging.SaveLog(nameof(VaKoLinkConnection), ex);
            Status = $"Не удалось {action}. {ex.Message}";
        }
        Changed?.Invoke();
    }

    public Task ToggleAsync() => TransitionAsync(async () =>
    {
        if (NeedsDisconnect)
        {
            try
            {
                await SaveResumeAsync(null);
            }
            finally
            {
                await StopAsync();
            }
        }
        else
        {
            await StartAsync();
        }
    });

    public Task SelectAsync(bool useTun) => TransitionAsync(async () =>
    {
        if (UseTun == useTun)
        {
            return;
        }
        var reconnect = _connected;
        if (NeedsDisconnect)
        {
            await StopAsync();
        }

        var previous = UseTun;
        config.VaKoLinkUseTun = useTun;
        if (await ConfigHandler.SaveConfig(config) != 0)
        {
            config.VaKoLinkUseTun = previous;
            throw new IOException("Не удалось сохранить выбранный режим.");
        }
        Status = "Отключено";
        if (reconnect)
        {
            await StartAsync();
        }
    });

    public Task ReloadAsync() => TransitionAsync(async () =>
    {
        if (_connectedProfile is not { } previous)
        {
            return;
        }
        var profile = await AppManager.Instance.GetProfileItem(config.VaKoLinkResume?.NodeId ?? previous.IndexId);
        if (profile is null)
        {
            Status = $"Нода «{previous.Remarks}» исчезла из подписки. Выберите другую ноду.";
            return;
        }
        await ReplaceConnectionAsync(profile, previous);
    });

    public Task SwitchNodeAsync(string nodeId) => TransitionAsync(async () =>
    {
        if (_connectedProfile is not { } previous || nodeId == previous.IndexId)
        {
            return;
        }
        var profile = await AppManager.Instance.GetProfileItem(nodeId);
        if (profile is null)
        {
            Status = "Выбранная нода больше недоступна. Выберите другую ноду.";
            return;
        }
        await ReplaceConnectionAsync(profile, previous);
    }, wait: false);

    private async Task ReplaceConnectionAsync(ProfileItem target, ProfileItem previous)
    {
        IsSwitchingNode = true;
        Changed?.Invoke();
        var restartTransport = !UseTun && IsTransportRunning?.Invoke() == true;
        string? recoveredFrom = null;
        try
        {
            await StopAsync();
            await StartAsync(target);
        }
        catch (Exception ex)
        {
            Logging.SaveLog(nameof(VaKoLinkConnection), ex);
            if (IsConnected)
            {
                Status = $"Не удалось переключить ноду. {ex.Message}";
                return;
            }
            try
            {
                await StopAsync();
                await StartAsync(previous);
                recoveredFrom = ex.Message;
            }
            catch (Exception rollback)
            {
                throw new InvalidOperationException($"Новая нода не подключилась. {ex.Message} " +
                    $"Прежнее подключение не восстановлено. {rollback.Message}", rollback);
            }
        }

        if (recoveredFrom is not null)
        {
            Status = $"Прежняя нода восстановлена. Новая нода не подключилась. {recoveredFrom}";
        }
        IsSwitchingNode = false;
        Changed?.Invoke();
        if (restartTransport && RestartTransport is { } restart)
        {
            _restartingTransport = true;
            try
            {
                await restart();
            }
            finally
            {
                _restartingTransport = false;
            }
        }
    }

    public async Task<bool> RunWhileDisconnectedAsync(Func<Task> operation)
    {
        if (!await _transition.WaitAsync(0))
        {
            return false;
        }
        try
        {
            if (!Ready || _closing || NeedsDisconnect)
            {
                return false;
            }
            Busy = true;
            Changed?.Invoke();
            await operation();
            return true;
        }
        finally
        {
            Busy = false;
            _transition.Release();
            Changed?.Invoke();
        }
    }

    public async Task<bool> ShutdownAsync()
    {
        _closing = true;
        await _transition.WaitAsync();
        try
        {
            await StopAsync();
            return true;
        }
        catch (Exception ex)
        {
            _closing = false;
            Logging.SaveLog(nameof(VaKoLinkConnection), ex);
            Status = $"Не удалось завершить отключение. {ex.Message}";
            Changed?.Invoke();
            return false;
        }
        finally
        {
            _transition.Release();
        }
    }

    private async Task TransitionAsync(Func<Task> action, bool wait = true)
    {
        if (wait)
        {
            await _transition.WaitAsync();
        }
        else if (!await _transition.WaitAsync(0))
        {
            return;
        }
        try
        {
            if (!Ready || _closing)
            {
                return;
            }
            Busy = true;
            Changed?.Invoke();
            await action();
        }
        catch (Exception ex)
        {
            Logging.SaveLog(nameof(VaKoLinkConnection), ex);
            try
            {
                await StopAsync();
                if (config.VaKoLinkResume is not null)
                {
                    await SaveResumeAsync(null);
                }
                Status = $"Ошибка подключения. {ex.Message}";
            }
            catch (Exception cleanup)
            {
                Logging.SaveLog(nameof(VaKoLinkConnection), cleanup);
                Status = $"Ошибка. {ex.Message} Восстановление не завершено. {cleanup.Message}";
            }
        }
        finally
        {
            IsConnecting = false;
            IsSwitchingNode = false;
            Busy = false;
            _transition.Release();
            Changed?.Invoke();
        }
    }

    private async Task StartAsync(ProfileItem? profile = null)
    {
        IsConnecting = true;
        Status = "Подключение…";
        Changed?.Invoke();
        var useTun = UseTun;
        var routing = VaKoLinkRouting.ForMode(useTun);
        Logging.SaveLog($"VaKoLink routing: {(useTun ? "TUN" : "Proxy")} -> {routing.Remarks}");

        profile ??= await ConfigHandler.GetDefaultServer(config);
        if (profile is null)
        {
            throw new InvalidOperationException("Выберите профиль сервера в списке.");
        }
        if (useTun && !Utils.IsAdministrator())
        {
            throw new InvalidOperationException("Для TUN запустите VaKoLink от имени администратора.");
        }

        var port = AppManager.Instance.GetLocalPort(EInboundProtocol.socks);
        if (HasProxyListener(port))
        {
            throw new InvalidOperationException($"Локальный порт прокси {port} уже занят.");
        }
        if (useTun && IsTunReady())
        {
            throw new InvalidOperationException($"Интерфейс {_tunName} уже существует.");
        }
        var sessionConfig = JsonUtils.DeepCopy(config) ?? throw new InvalidOperationException("Не удалось прочитать настройки профиля.");
        sessionConfig.TunModeItem.EnableTun = useTun;
        var contexts = await CoreConfigContextBuilder.BuildAll(sessionConfig, profile, routing, useTun ? _tunName : null);
        if (!contexts.Success)
        {
            throw new InvalidOperationException(string.Join(Environment.NewLine, contexts.CombinedValidatorResult.Errors));
        }
        var main = contexts.MainResult.Context;
        var pre = contexts.PreSocksResult?.Context;
        if (main.Node.ConfigType == EConfigType.Custom || pre?.Node.ConfigType == EConfigType.Custom)
        {
            throw new InvalidOperationException("Пользовательский конфиг ядра не поддерживает применение правил VaKoLink. Выберите обычный профиль сервера.");
        }
        if (UsesCustomTemplate(main) || pre is not null && UsesCustomTemplate(pre))
        {
            throw new InvalidOperationException("Полный шаблон конфигурации ядра заменяет правила VaKoLink. Отключите шаблон в расширенных настройках.");
        }

        _requiresPreCore = pre is not null;
        _ownsCore = true;
        _ownsTun = useTun;
        var core = CoreManager.Instance;
        await core.LoadCore(main, pre, checkedLaunch: true);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        try
        {
            while (core.IsConnectionRunning(_requiresPreCore) && (!HasProxyListener(port) || useTun && !IsTunReady()))
            {
                await Task.Delay(100, timeout.Token);
            }
        }
        catch (OperationCanceledException)
        {
            throw new TimeoutException(useTun ? "Ядро не подняло интерфейс TUN." : $"Ядро не открыло локальный порт прокси {port}.");
        }
        if (!core.IsConnectionRunning(_requiresPreCore))
        {
            throw new InvalidOperationException(core.ConnectionExitReason());
        }

        // The shipped routing presets send this public HTTPS endpoint through the selected outbound.
        var webProxy = new WebProxy($"socks5://{Global.Loopback}:{port}");
        var responseTime = await ConnectionHandler.GetRealPingTime(webProxy, Global.SpeedPingTestUrls[0],
            CancellationToken.None, requireSuccess: true);
        if (responseTime < 0)
        {
            throw new IOException("Выбранная нода не ответила на проверочный HTTPS-запрос.");
        }
        if (!core.IsConnectionRunning(_requiresPreCore) || useTun && !IsTunReady())
        {
            throw new IOException("Подключение прервалось во время проверки связи.");
        }
        if (!useTun)
        {
            _proxy = new();
            _proxy.Enable(config, port);
        }

        var previousIndex = config.IndexId;
        config.IndexId = profile.IndexId;
        try
        {
            await SaveResumeAsync(new(profile.IndexId, profile.Remarks, useTun));
        }
        catch
        {
            config.IndexId = previousIndex;
            throw;
        }
        ConnectedProxyPort = useTun ? null : port;
        _monitor = new();
        ConnectedSessionToken = _monitor.Token;
        _connectedProfile = profile;
        _connected = true;
        IsConnecting = false;
        Status = "Подключено";
        _ = MonitorAsync(useTun, port, ConnectedSessionToken);
    }

    private async Task StopAsync()
    {
        if (_ownsCore && BeforeCoreStop is not null)
        {
            await BeforeCoreStop();
        }
        _monitor?.Cancel();
        _monitor?.Dispose();
        _monitor = null;
        _connected = false;
        _connectedProfile = null;
        ConnectedProxyPort = null;
        ConnectedSessionToken = default;
        try
        {
            _proxy?.Restore();
            _proxy = null;
        }
        finally
        {
            if (_ownsCore)
            {
                await CoreManager.Instance.CoreStop(checkExit: true);
                if (_ownsTun)
                {
                    for (var attempt = 0; attempt < 20 && IsTunReady(); attempt++)
                    {
                        await Task.Delay(100);
                    }
                    if (IsTunReady())
                    {
                        throw new InvalidOperationException($"Интерфейс {_tunName} ещё активен.");
                    }
                    _ownsTun = false;
                }
                _ownsCore = false;
            }
        }
        Status = "Отключено";
    }

    private async Task MonitorAsync(bool useTun, int port, CancellationToken token)
    {
        try
        {
            while (true)
            {
                await Task.Delay(500, token);
                if (token.IsCancellationRequested)
                {
                    return;
                }
                var core = CoreManager.Instance;
                if (!core.IsConnectionRunning(_requiresPreCore))
                {
                    throw new InvalidOperationException(core.ConnectionExitReason());
                }
                if (useTun ? !IsTunReady() : !HasProxyListener(port) || _proxy?.IsEnabled() != true)
                {
                    throw new InvalidOperationException("Локальный интерфейс подключения стал недоступен.");
                }
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            await TransitionAsync(async () =>
            {
                if (!token.IsCancellationRequested)
                {
                    await SaveResumeAsync(null);
                    await Task.FromException(ex);
                }
            });
        }
    }

    private async Task SaveResumeAsync(VaKoLinkResumeState? state)
    {
        var previous = config.VaKoLinkResume;
        config.VaKoLinkResume = state;
        if (await ConfigHandler.SaveConfig(config) != 0)
        {
            config.VaKoLinkResume = previous;
            throw new IOException("Не удалось сохранить состояние подключения.");
        }
    }

    private bool IsTunReady() =>
        NetworkInterface.GetAllNetworkInterfaces().Any(nic => nic.Name == _tunName && nic.OperationalStatus == OperationalStatus.Up);

    private static bool HasProxyListener(int port) =>
        IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(endpoint => endpoint.Port == port);

    private static bool UsesCustomTemplate(CoreConfigContext context) =>
        context.FullConfigTemplate is { Enabled: true } template &&
        !string.IsNullOrWhiteSpace(context.IsTunEnabled ? template.TunConfig : template.Config);
}
