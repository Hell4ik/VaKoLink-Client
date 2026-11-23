namespace v2rayN.Manager;

internal sealed record TransportState(bool Running, bool CanRelease, bool CleanupConfirmed, string? Failure,
    TransportEvidence? Evidence = null);

internal interface ITransportSession
{
    Task StartAsync();
    Task StopAsync();
    TransportState Read();
}

internal sealed class VaKoLinkTransport(Func<Task<ITransportSession>> prepare, Func<string> vpnState)
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private ITransportSession? _session;
    private CancellationTokenSource? _monitor;
    private string _incidentId = "";
    private string _stage = "Подготовка";
    private TransportCause? _cleanupError;
    private TransportState? _lastState;
    public TransportIncident? LastIncident { get; private set; }

    public event Action? Changed;
    public bool Busy { get; private set; }
    public bool IsRunning { get; private set; }
    public bool NeedsStop => _session is not null;
    public bool CleanupPending { get; private set; }
    public string? DiagnosticFailure { get; private set; }
    public string Status { get; private set; } = "Маршрутизация остановлена";

    public Task ToggleAsync() => RunAsync(async () =>
    {
        if (_session is not null)
        {
            _stage = "Остановка";
            await StopSessionAsync();
            if (CleanupPending)
                await ReportAsync(null, _lastState?.Failure ?? "TUN_BASELINE_AFTER_MISMATCH");
            return;
        }

        _incidentId = Guid.NewGuid().ToString("N");
        _stage = "Подготовка";
        _cleanupError = null;
        _lastState = null;
        Status = "Маршрутизация запускается…";
        Changed?.Invoke();
        try
        {
            _session = await prepare();
            _stage = "Запуск";
            await _session.StartAsync();
            var state = _lastState = _session.Read();
            if (!state.Running || state.Failure is not null)
            {
                throw new InvalidOperationException(state.Failure ?? "Ядро маршрутизации не подтвердило запуск.");
            }

            IsRunning = true;
            Status = state.Evidence?.SelectedApplications is { } count
                ? $"Маршрутизация работает · приложений: {count}" : "Маршрутизация работает";
            _monitor = new CancellationTokenSource();
            _ = MonitorAsync(_monitor.Token);
        }
        catch
        {
            if (_session is not null)
            {
                try
                {
                    await StopSessionAsync();
                }
                catch (Exception cleanup)
                {
                    _cleanupError = TransportIncidents.Cause(cleanup.Message, "Очистка", cleanup);
                }
            }
            throw;
        }
    });

    public Task StopBeforeVpnAsync() => RunAsync(async () =>
    {
        if (_session is not null)
        {
            _stage = "Остановка";
            await StopSessionAsync();
            if (CleanupPending)
                await ReportAsync(null, _lastState?.Failure ?? "TUN_BASELINE_AFTER_MISMATCH");
        }
    }, propagate: true);

    private async Task RunAsync(Func<Task> transition, bool propagate = false)
    {
        await _gate.WaitAsync();
        try
        {
            Busy = true;
            DiagnosticFailure = null;
            Changed?.Invoke();
            await transition();
        }
        catch (OperationCanceledException)
        {
            Status = "Операция маршрутизации отменена.";
            if (propagate) throw;
        }
        catch (Exception ex)
        {
            await ReportAsync(ex, ex is AggregateException aggregate ? aggregate.InnerExceptions.FirstOrDefault()?.Message : ex.Message);
            if (_session is not null)
            {
                Status += " Остановка маршрутизации не подтверждена.";
            }
            if (propagate)
            {
                throw;
            }
        }
        finally
        {
            Busy = false;
            _gate.Release();
            Changed?.Invoke();
        }
    }

    private async Task<TransportState> StopSessionAsync()
    {
        var session = _session!;
        Status = "Маршрутизация останавливается…";
        Changed?.Invoke();
        await session.StopAsync();
        var state = _lastState = session.Read();
        IsRunning = state.Running && state.Failure is null;
        if (!state.CanRelease)
        {
            throw new InvalidOperationException(state.Failure ?? "Ядро маршрутизации не подтвердило завершение.");
        }

        CleanupPending = !state.CleanupConfirmed;
        if (!CleanupPending)
        {
            _session = null;
        }
        _monitor?.Cancel();
        _monitor?.Dispose();
        _monitor = null;
        Status = state.CleanupConfirmed
            ? "Маршрутизация остановлена"
            : $"Маршрутизация остановлена. Проверка очистки не завершена. {DescribeFailure(state.Failure)}";
        return state;
    }

    private async Task MonitorAsync(CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                await Task.Delay(500, token);
                await _gate.WaitAsync(token);
                var notify = false;
                try
                {
                    if (_session is null || token.IsCancellationRequested)
                    {
                        return;
                    }
                    var state = _session.Read();
                    if (!state.Running || state.Failure is not null)
                    {
                        notify = true;
                        IsRunning = false;
                        Busy = true;
                        _lastState = state;
                        _stage = "Мониторинг";
                        try { await StopSessionAsync(); }
                        catch (Exception cleanup) { _cleanupError = TransportIncidents.Cause(cleanup.Message, "Очистка", cleanup); }
                        await ReportAsync(null, state.Failure);
                        return;
                    }
                }
                catch (Exception ex)
                {
                    notify = true;
                    IsRunning = false;
                    _stage = "Мониторинг";
                    if (_session is not null)
                    {
                        try { await StopSessionAsync(); }
                        catch (Exception cleanup) { _cleanupError = TransportIncidents.Cause(cleanup.Message, "Очистка", cleanup); }
                    }
                    await ReportAsync(ex, ex.Message);
                    return;
                }
                finally
                {
                    Busy = false;
                    _gate.Release();
                    if (notify)
                    {
                        Changed?.Invoke();
                    }
                }
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
        }
    }

    private async Task ReportAsync(Exception? error, string? code)
    {
        var primary = TransportIncidents.Cause(code, _stage, error);
        var evidence = _lastState?.Evidence ?? (error as TransportPreparationException)?.Evidence;
        var previous = LastIncident?.Id == _incidentId ? LastIncident : null;
        var report = TransportIncidents.Create(_incidentId, vpnState(), previous?.Primary ?? primary,
            _cleanupError ?? (_stage == "Остановка" && previous is not null ? primary : previous?.CleanupError),
            _lastState?.CleanupConfirmed, evidence ?? previous?.Evidence);
        LastIncident = report;
        Status = primary.Message;
        DiagnosticFailure = $"{report.RecordedAt:HH:mm:ss} · {primary.Stage} · {primary.Code} · {report.Id}";
        try { await Task.Run(() => TransportIncidents.Save(report)); }
        catch (Exception saveError) when (saveError is System.IO.IOException or UnauthorizedAccessException)
        {
            DiagnosticFailure += " · файл отчёта не сохранён";
        }
    }

    internal static string DescribeFailure(string? code) => code switch
    {
        "GAME_PASSIVE_SCOPE_INVALID" => "Не удалось подготовить список наблюдаемых приложений. Сохраните отчёт в «Диагностике».",
        "TUN_CORE_CHECK_REJECTED" => "Ядро отклонило настройки маршрутизации. Сохраните отчёт в «Диагностике».",
        "SELECTED_APPLICATIONS_REQUIRED" => "Выберите от одного до 32 приложений для маршрутизации.",
        "SELECTED_APPLICATION_MISSING" => "Файл одного из выбранных приложений не найден. Проверьте список.",
        "SELECTED_APPLICATION_UNTRUSTED" => "Подпись одного из выбранных приложений не подтверждена. Проверьте список.",
        "SELECTED_APPLICATION_CHANGED" => "Файл приложения изменился во время запуска. Повторите проверку.",
        "PROXY_LOOP_GUARD_INVALID" => "В списке есть приложение, через которое уже работает прокси. Удалите его из списка маршрутизации.",
        "AION_STEAM_NOT_FOUND" => "Маршрутизация не нашла поддерживаемую установку игры в Steam.",
        "AION_STEAM_LAUNCHER_UNKNOWN" => "Маршрутизация не смогла распознать данные установки игры в Steam.",
        "DISCORD_SIGNED_CLIENT_NOT_FOUND" => "Маршрутизация не нашла установленный клиент голосовой связи с доверенной подписью.",
        "AION_SIGNATURE_NOT_TRUSTED" or "TUN_AION_SIGNATURE_UNTRUSTED" =>
            "Маршрутизация не смогла подтвердить подпись игрового клиента. Проверьте файлы игры через Steam.",
        "AION_UPDATED_RECHECK_REQUIRED" or "DISCORD_UPDATED_RECHECK_REQUIRED" or "TUN_AION_IMAGE_CHANGED" =>
            "Файлы приложения изменились. Запустите маршрутизацию заново для повторной проверки.",
        "TUN_NON_TUN_ADDRESS_CHANGED" =>
            "При запуске маршрутизации изменились IP-адреса другого сетевого интерфейса. Дождитесь стабилизации сети и попробуйте снова.",
        "TUN_NON_TUN_DNS_CHANGED" or "TUN_NON_TUN_INTERFACE_CHANGED" or "TUN_NON_TUN_ADAPTER_CHANGED" or
        "TUN_NON_TUN_ROUTE_CHANGED" or "TUN_BASELINE_NOT_SETTLED" =>
            "Сетевые настройки изменились во время запуска Transport. Дождитесь стабилизации сети и попробуйте снова.",
        "PROXY_UDP_ASSOCIATE_REJECTED" or "PROXY_UDP_RESPONSE_INVALID" or "PROXY_UDP_RESPONSE_TIMEOUT" or
        "DISCORD_UDP_CHAIN_NOT_VERIFIED" => "Маршрутизация не смогла подтвердить передачу UDP через прокси.",
        "PROXY_NOT_FOUND" or "PROXY_NOT_READY" or "PROXY_LOCAL_SOCKET_UNAVAILABLE" or "PROXY_UPSTREAM_UNRESPONSIVE" =>
            "Маршрутизация не смогла подтвердить доступность локального прокси VaKoLink.",
        "TUN_PREFLIGHT_CONFLICT" => "Обнаружен работающий игровой клиент или другой сетевой обработчик. Запустите маршрутизацию перед запуском игры.",
        "TUN_EXISTING_TUN_OR_DEFAULT_NOT_PHYSICAL" => "Маршрутизация обнаружила другой туннель или нестандартный маршрут по умолчанию.",
        "TUN_SYSTEM_PROXY_CHANGED" => "Во время запуска Transport изменился системный прокси Windows.",
        "TUN_FIREWALL_PROFILES_CHANGED" => "Во время запуска Transport изменились параметры брандмауэра Windows.",
        null => "Сессия маршрутизации завершилась неожиданно.",
        _ => "Не удалось завершить операцию маршрутизации. Подробности в диагностике."
    };
}
