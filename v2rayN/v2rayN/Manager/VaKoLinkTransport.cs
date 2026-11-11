namespace v2rayN.Manager;

internal sealed record TransportState(bool Running, bool CanRelease, bool CleanupConfirmed, string? Failure);

internal interface ITransportSession
{
    Task StartAsync();
    Task StopAsync();
    TransportState Read();
}

internal sealed class VaKoLinkTransport(Func<Task<ITransportSession>> prepare)
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private ITransportSession? _session;
    private CancellationTokenSource? _monitor;

    public event Action? Changed;
    public bool Busy { get; private set; }
    public bool IsRunning { get; private set; }
    public bool NeedsStop => _session is not null;
    public bool CleanupPending { get; private set; }
    public string? DiagnosticFailure { get; private set; }
    public string Status { get; private set; } = "Transport остановлен";

    public Task ToggleAsync() => RunAsync(async () =>
    {
        if (_session is not null)
        {
            await StopSessionAsync();
            return;
        }

        Status = "Transport запускается…";
        Changed?.Invoke();
        try
        {
            _session = await prepare();
            await _session.StartAsync();
            var state = _session.Read();
            if (!state.Running || state.Failure is not null)
            {
                throw new InvalidOperationException(state.Failure ?? "Transport не подтвердил запуск.");
            }

            IsRunning = true;
            Status = "Transport работает";
            _monitor = new CancellationTokenSource();
            _ = MonitorAsync(_monitor.Token);
        }
        catch (Exception startup)
        {
            if (_session is not null)
            {
                try
                {
                    await StopSessionAsync();
                }
                catch (Exception cleanup)
                {
                    throw new InvalidOperationException($"{startup.Message} Ошибка остановки: {cleanup.Message}", startup);
                }
            }
            throw;
        }
    });

    public Task StopBeforeVpnAsync() => RunAsync(async () =>
    {
        if (_session is not null)
        {
            await StopSessionAsync();
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
        catch (Exception ex)
        {
            DiagnosticFailure = $"Сбой Transport · 0x{ex.HResult:X8}";
            Status = $"Ошибка Transport. {ex.Message}";
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

    private async Task StopSessionAsync()
    {
        var session = _session!;
        Status = "Transport останавливается…";
        Changed?.Invoke();
        await session.StopAsync();
        var state = session.Read();
        IsRunning = state.Running && state.Failure is null;
        if (!state.CanRelease)
        {
            throw new InvalidOperationException(state.Failure ?? "Transport не подтвердил завершение своего ядра.");
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
            ? "Transport остановлен"
            : $"Transport остановлен. Проверка очистки не завершена. {state.Failure}";
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
                        await StopSessionAsync();
                        DiagnosticFailure = "Сессия Transport завершилась";
                        Status = $"Ошибка Transport. {state.Failure ?? "Сессия завершилась неожиданно."}";
                        return;
                    }
                }
                catch (Exception ex)
                {
                    notify = true;
                    IsRunning = false;
                    DiagnosticFailure = $"Проверка Transport · 0x{ex.HResult:X8}";
                    Status = $"Ошибка Transport. {ex.Message}";
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
}
