using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using VakoLink.AntiDpi.Windows;

namespace VakoLink.AionTransport.Proxy;

public static class Product
{
    public const string Name = "VaKoLink Transport", Version = "1.0.4", DisplayVersion = "v.1.0.4";
    public const string ReadyText = "Прокси готов! Нажмите „Включить“";
    public const string EnabledText = "Для остановки работы нажмите „Выключить“";
}

public sealed class UserEventLog
{
    private readonly object _gate = new(); private readonly Queue<string> _lines = new(); private int _length;
    public long Revision { get; private set; }
    public const int MaxLines = 600, MaxCharacters = 96000;
    public void Add(string level, string message, DateTimeOffset? time = null)
    {
        // Only controller-generated messages and safe error codes; no stderr/config/traffic strings.
        string safe = Regex.Replace(message, @"(?i)(?:https?|vless|vmess|trojan|ss)://\S+", "[ссылка скрыта]");
        safe = Regex.Replace(safe, @"(?i)\b(password|token|secret|uuid|key)\s*[:=]\s*\S+", "$1=[скрыто]");
        safe = Regex.Replace(safe, @"[A-Za-z]:\\\S+", "[путь скрыт]").Replace('\r', ' ').Replace('\n', ' ');
        if (safe.Length > 2000) safe = safe[..2000];
        string line = $"{(time ?? DateTimeOffset.Now).ToLocalTime():HH:mm:ss} [{level}] {safe}";
        lock (_gate) { _lines.Enqueue(line); _length += line.Length + Environment.NewLine.Length; while (_lines.Count > MaxLines || _length > MaxCharacters) _length -= _lines.Dequeue().Length + Environment.NewLine.Length; Revision++; }
    }
    public string Text { get { lock (_gate) return string.Join(Environment.NewLine, _lines); } }
    public void Clear() { lock (_gate) { _lines.Clear(); _length = 0; Revision++; } }
}

public sealed record PreparedTransport(LocalProxyEndpoint Proxy, GameInstall Game, IReadOnlyList<DiscordComponentPin> Discord);
public sealed record UserRunState(bool Running, bool Cleanup, string? Failure, bool CoreCreated = false, bool CoreExited = false,
    int? ExitCode = null, IReadOnlyList<TunLifecycleEvent>? Lifecycle = null, object? Native = null, object? Discord = null,
    string? ConfigurationSha256 = null, bool GameObserved = false, bool DiscordObserved = false,
    IReadOnlyList<NetworkIsolationCheck>? StartupIsolation = null, ProxyProbe? StartupProxyProbe = null,
    ProxyCleanupAssessment? CleanupAssessment = null, bool CanExitWithPendingAudit = false);
public interface IUserTransportRun
{
    Task StartAsync(); Task StopAsync(); UserRunState Read();
}
public interface IUserTransportPlatform
{
    ProxyProbe? LastProbe => null;
    Task<PreparedTransport> PrepareAsync(Action<string, string> log);
    Task<PreparedTransport> RevalidateAsync(PreparedTransport prepared, Action<string, string> log);
    Task<ProxyProbe> ProbeAsync(PreparedTransport prepared);
    IUserTransportRun Create(PreparedTransport prepared);
}

public sealed class LocalTransportPlatform(int guiPid, int socksPort) : IUserTransportPlatform
{
    private async Task<IReadOnlyList<LocalProxyEndpoint>> DiscoverClientAsync() =>
        (await LocalProxy.DiscoverAsync(_discovery))
            .Where(endpoint => endpoint.GuiPid == guiPid && endpoint.Port == socksPort).ToArray();

    public ProxyProbe? LastProbe { get; private set; }
    private readonly string _discovery = Path.Combine(AppContext.BaseDirectory, "tools", "Discover-LocalProxy.ps1");
    public async Task<PreparedTransport> PrepareAsync(Action<string, string> log)
    {
        LastProbe = null;
        log("ИНФО", "Автоматическое обнаружение работающего V2rayN и локальных входов.");
        var found = await DiscoverClientAsync();
        if (found.Count == 0) throw new IOException("PROXY_NOT_FOUND");
        if (found.Select(p => p.GuiPid).Distinct().Count() > 1) throw new IOException("PROXY_MULTIPLE_CLIENTS");
        log("ИНФО", $"Найдено локальных входов: {found.Count}. Проверяем протокол и передачу данных.");
        LocalProxyEndpoint? selected = null; string? failure = null;
        foreach (var candidate in found.OrderBy(p => p.Port))
        {
            candidate.VerifyAlive(); var probe = LastProbe = await LocalProxy.ProbeAsync(candidate);
            ProbeLog(log, candidate.Port, probe);
            if (probe.Ready) { selected = candidate; break; }
            failure = probe.Failure;
        }
        if (selected is null) throw new IOException(failure ?? "PROXY_NOT_READY");
        log("ИНФО", $"Выбран проверенный SOCKS5-вход V2rayN: локальный порт {selected.Port}.");
        if (File.Exists(ProxyJournal.MarkerPath))
        {
            log("ИНФО", "До состояния готовности проверяем завершение предыдущей операции. Сеть не сбрасывается.");
            var recovery = await ProxyTunSession.RecoverJournalAsync(Path.Combine(AppContext.BaseDirectory, "tools", "ProxyNetworkState.ps1"), selected.Members);
            bool exact = (bool?)recovery["GlobalStateRestoredClaimed"] == true;
            log(exact ? "ИНФО" : "ВНИМАНИЕ", exact ? "Предыдущая операция завершена; исходный снимок совпадает. Журнал архивирован." :
                "Собственные ресурсы предыдущей операции отсутствуют; журнал безопасно архивирован. Состояние других интерфейсов отличается и не восстанавливалось; сведения сохранены в safe-recovery.");
        }
        return DiscoverClients(selected, log);
    }
    private static PreparedTransport DiscoverClients(LocalProxyEndpoint proxy, Action<string, string> log)
    {
        log("ИНФО", "Проверка установленных приложений и подписей файлов; запускать игру для этого не нужно.");
        GameInstall? game = null;
        string settings = Path.Combine(ProxyTunPlan.Root, "settings.dpapi");
        JsonObject? saved = null;
        if (File.Exists(settings))
        {
            try { saved = TunPrivateStore.ReadProtected(settings); }
            catch { log("ВНИМАНИЕ", "Сохранённые сведения об установке не прочитаны; выполняется независимый поиск Steam."); }
        }
        if (saved?["Root"] is not null && saved["SteamId"] is not null && Directory.Exists((string)saved["Root"]!))
            game = GameInstall.FromRoot((string)saved["Root"]!, (string)saved["SteamId"]!);
        game ??= GameInstall.Find().FirstOrDefault();
        if (game is null) throw new IOException("AION_STEAM_NOT_FOUND");
        game.VerifyUnchanged(); var discord = DiscordMediaProfile.Discover();
        if (discord.Count == 0) throw new IOException("DISCORD_SIGNED_CLIENT_NOT_FOUND");
        log("ИНФО", "Подписи Aion и Discord проверены. Общие правила готовы; неподтверждённые компоненты не добавлялись.");
        return new(proxy, game, discord);
    }
    public async Task<PreparedTransport> RevalidateAsync(PreparedTransport p, Action<string, string> log)
    {
        LastProbe = null;
        log("ИНФО", "Повторное обнаружение текущего входа V2rayN перед новым включением; старые PID и параметры ноды не переиспользуются.");
        var fresh = ProxyEndpointRefresh.PreviousListenerOrSingle(p.Proxy, await DiscoverClientAsync());
        if (fresh is null) return await PrepareAsync(log);
        fresh.VerifyAlive();
        if (ProxyEndpointRefresh.Identity(fresh) != ProxyEndpointRefresh.Identity(p.Proxy))
            log("ИНФО", "V2rayN перезапущен, изменён порт или конфигурация. Новая привязка принята для нового запуска; старый транспорт не возобновляется.");
        var current = DiscoverClients(fresh, log);
        if (current.Game.Sha256 != p.Game.Sha256 || !current.Discord.SequenceEqual(p.Discord))
            log("ИНФО", "Обнаружлено обновление приложения. Доверенная подпись повторно проверена; привязка обновлена до запуска транспорта.");
        return current;
    }
    public async Task<ProxyProbe> ProbeAsync(PreparedTransport p) { p.Proxy.VerifyAlive(); return LastProbe = await LocalProxy.ProbeAsync(p.Proxy); }
    internal static void ProbeLog(Action<string, string> log, int port, ProxyProbe p)
    {
        log(p.TcpResponse ? "ИНФО" : "ВНИМАНИЕ", $"Порт {port}: TCP — {(p.TcpResponse ? "получен ответ через SOCKS5" : "ответ не подтверждён")}.");
        log(p.UdpResponse ? "ИНФО" : "ВНИМАНИЕ", $"Порт {port}: UDP — {(p.UdpResponse ? "получен и проверен ответ датаграммы" : "ответ не подтверждён")}{(p.Failure is null ? "." : "; причина: " + p.Failure + ".")}");
        foreach (var a in p.Attempts ?? [])
            log(a.Passed || a.Failure == "PROBE_SUPERSEDED_AFTER_SUCCESS" ? "ИНФО" : "ВНИМАНИЕ", $"Проверка {a.Protocol.ToUpperInvariant()} · {a.Target}: этап={a.Stage}; SOCKS5={(a.Socks5 ? "да" : "нет")}; {a.DurationMs} мс; {(a.Passed ? "ответ проверен" : a.Failure == "PROBE_SUPERSEDED_AFTER_SUCCESS" ? "проверка завершена после проверенного ответа альтернативной цели" : a.Failure)}.");
    }
    public IUserTransportRun Create(PreparedTransport p) => new LocalRun(p);
    private sealed class LocalRun : IUserTransportRun
    {
        private readonly ProxyTunSession _session;
        public LocalRun(PreparedTransport p) => _session = new(p.Proxy, p.Game.Main, p.Game.Sha256,
            Path.Combine(AppContext.BaseDirectory, "tools", "ProxyNetworkState.ps1"), discord: p.Discord);
        public Task StartAsync() => _session.StartAsync(); public Task StopAsync() => _session.StopAsync();
        public UserRunState Read()
        {
            var e = _session.Evidence;
            return new(e.Running, e.CleanupConfirmed, e.Failure, e.CoreCreated, e.CoreExited, e.CoreExitCode, e.Lifecycle,
                e, _session.DiscordEvidence, _session.ConfigurationSha256, e.Flows.Any(f => f.SelectedMain && f.Outbound == "v2ray-local"),
                e.Flows.Any(f => f.Component == "Discord.exe" && f.Network == "udp" && f.Outbound == "discord-media"), e.StartupIsolation, e.StartupProxyProbe,
                e.CleanupAssessment, !e.Running && (!e.CoreCreated || e.CoreExited) && e.SecretConfigurationDeleted);
        }
    }
}

public enum UserTransportPhase { Preparing, Unavailable, Ready, Starting, Enabled, Stopping, Error }
public sealed record UserTransportView(string Transport, string Proxy, string Button, string Information, bool CanToggle, bool Busy);

public sealed class UserTransportController
{
    private readonly IUserTransportPlatform _platform; private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly bool _persist; private PreparedTransport? _prepared; private IUserTransportRun? _run; private bool _proxyReady, _everReady, _gameLogged, _discordLogged;
    private string? _error, _observedFailure, _lastUdpProof; private DateTimeOffset _nextPrepare, _nextSave; private string? _report;
    private Task? _save; private readonly HashSet<string> _events = []; private readonly Queue<string> _eventOrder = new();
    private int _isolationLogged;
    private bool _startupProbeLogged;
    private readonly string _readinessReport = Guid.NewGuid().ToString("N"); private readonly Queue<object> _readinessHistory = new();
    public UserEventLog Log { get; } = new(); public UserTransportPhase Phase { get; private set; } = UserTransportPhase.Preparing;
    public object? PreparedScopeEvidence => _prepared is null ? null : new { AionPathSha256 = AionTunPlan.Hash(_prepared.Game.Main),
        DiscordPathSha256 = _prepared.Discord.Select(p => AionTunPlan.Hash(p.Path)).ToArray(), _prepared.Proxy.Port, Mode = "CombinedAionDiscord" };
    public event Action? Changed;
    public UserTransportController(IUserTransportPlatform platform, bool persist = true)
    { _platform = platform; _persist = persist; Log.Add("ИНФО", $"Запуск {Product.Name} {Product.DisplayVersion}."); }
    public bool Busy => _gate.CurrentCount == 0;
    public bool NeedsStop => _run is not null && (!_run.Read().Cleanup || _run.Read().Running);
    public bool CanExit => !Busy && (!NeedsStop || _run?.Read().CanExitWithPendingAudit == true);
    public UserTransportView View
    {
        get
        {
            var e = _run?.Read(); bool on = Phase == UserTransportPhase.Enabled && e?.Running == true && e.Failure is null;
            bool pendingCleanup = e is { Cleanup: false } && Phase is not (UserTransportPhase.Starting or UserTransportPhase.Preparing);
            string status = Phase == UserTransportPhase.Starting ? "Подключение…" : on || Phase == UserTransportPhase.Stopping && e?.Running == true && e.Failure is null ? "Включено" : "Выключен";
            string info = _error is not null ? Explain(_error) : Phase switch
            {
                UserTransportPhase.Preparing => "Подготовка…", UserTransportPhase.Starting => "Подключение… Подождите.",
                UserTransportPhase.Stopping => "Отключение… Подождите.", UserTransportPhase.Enabled when on => Product.EnabledText,
                UserTransportPhase.Ready when _proxyReady => Product.ReadyText, _ => "Прокси недоступен. Запустите V2rayN с выключенным TUN; проверка повторится автоматически."
            };
            return new(status, _proxyReady ? "Доступен · SOCKS5" : Phase == UserTransportPhase.Preparing ? "Обнаружение…" : "Недоступен",
                on || pendingCleanup || Phase == UserTransportPhase.Stopping ? "Выключить" : "Включить", info,
                !Busy && (on || pendingCleanup || _proxyReady && _prepared is not null && Phase == UserTransportPhase.Ready), Busy);
        }
    }
    private void Notify() => Changed?.Invoke();
    private void Add(string level, string text) => Log.Add(level, text);
    public async Task PrepareAsync()
    {
        if (!await _gate.WaitAsync(0)) return;
        try { if (NeedsStop) return; await PrepareCoreAsync(); }
        finally { _gate.Release(); Notify(); }
    }
    private async Task PrepareCoreAsync()
    {
        bool wasReady = _proxyReady; Phase = UserTransportPhase.Preparing; _error = null; _proxyReady = false; Notify();
        try
        {
            _prepared = await Task.Run(() => _platform.PrepareAsync(Add)); _proxyReady = true; Phase = UserTransportPhase.Ready;
            Add("ИНФО", wasReady ? "Доступность прокси подтверждена повторно." : _everReady ? "Доступность прокси восстановлена. Подготовка завершена." : "Прокси доступен. Подготовка завершена."); _everReady = true;
        }
        catch (Exception ex)
        {
            _prepared = null; _error = ProxyTunSession.SafeCode(ex);
            _proxyReady = _platform.LastProbe?.Ready == true;
            Phase = _proxyReady ? UserTransportPhase.Error : UserTransportPhase.Unavailable;
            Add("ВНИМАНИЕ", Explain(_error) + " Код: " + _error);
        }
        _nextPrepare = DateTimeOffset.UtcNow.AddSeconds(_proxyReady ? 45 : 15);
        await SaveReadinessAsync();
    }
    public async Task ToggleAsync()
    {
        if (!await _gate.WaitAsync(0)) return;
        try
        {
            if (NeedsStop || Phase == UserTransportPhase.Enabled) { await StopCoreAsync(); return; }
            if (_prepared is null || !_proxyReady || Phase != UserTransportPhase.Ready) return;
            _run = null; Phase = UserTransportPhase.Starting; _error = null; Notify(); Add("ИНФО", "Начало включения транспорта с общими правилами приложений.");
            try
            {
                _prepared = await Task.Run(() => _platform.RevalidateAsync(_prepared!, Add));
                _run = _platform.Create(_prepared); _events.Clear(); _eventOrder.Clear(); _isolationLogged = 0; _startupProbeLogged = false; _observedFailure = _lastUdpProof = null; _gameLogged = _discordLogged = false; _report = Guid.NewGuid().ToString("N");
                await Task.Run(_run.StartAsync); Observe();
                if (!_run.Read().Running || _run.Read().Failure is not null) throw new IOException(_run.Read().Failure ?? "TRANSPORT_NOT_RUNNING");
                Phase = UserTransportPhase.Enabled; Add("ИНФО", "Транспорт успешно включён. Общие правила активны.");
            }
            catch (Exception ex)
            {
                _error = _run?.Read().Failure ?? ProxyTunSession.SafeCode(ex); _observedFailure = _error; Phase = UserTransportPhase.Error;
                if (_run is not null)
                {
                    try { await Task.Run(_run.StopAsync); } catch (Exception stop) { Add("ОШИБКА", "Ошибка завершения: " + ProxyTunSession.SafeCode(stop)); } Observe();
                    var stopped = _run.Read(); if (stopped.CoreCreated && stopped.CoreExited) Add("ИНФО", $"Ядро завершено с кодом {stopped.ExitCode?.ToString() ?? "неизвестен"}; очистка: {(stopped.Cleanup ? "подтверждена" : "не подтверждена")}.");
                }
                Add("ОШИБКА", "Включение не выполнено. " + Explain(_error) + " Код: " + _error);
                _proxyReady = false; _nextPrepare = DateTimeOffset.UtcNow.AddSeconds(15);
            }
            await SaveReportAsync();
            await SaveReadinessAsync();
        }
        finally { _gate.Release(); Notify(); }
    }
    private async Task StopCoreAsync(bool recheckProxy = true)
    {
        if (_run is null) return;
        Phase = UserTransportPhase.Stopping; _error = null; Notify(); Add("ИНФО", "Начало штатного выключения транспорта.");
        try
        {
            await Task.Run(_run.StopAsync); Observe(); var e = _run.Read();
            if (e.CoreCreated) Add(e.CoreExited ? "ИНФО" : "ОШИБКА", $"Завершение ядра: {(e.CoreExited ? "подтверждено" : "не подтверждено")}; код выхода: {e.ExitCode?.ToString() ?? "неизвестен"}.");
            if (!e.Cleanup) throw new IOException(e.Failure ?? "TUN_OWN_RESOURCES_NOT_RELEASED");
            if (e.CleanupAssessment is { GlobalBaselineEqual: false })
                Add("ВНИМАНИЕ", "Собственные ресурсы освобождены. Сеть Windows отличается от исходного снимка; чужие параметры не откатывались. Различия сохранены в отчёте.");
            Add("ИНФО", "Транспорт выключен. Очистка собственных сетевых изменений подтверждена."); await SaveReportAsync();
            _run = null;
            if (!recheckProxy) { Phase = UserTransportPhase.Unavailable; return; }
            _prepared = null; _proxyReady = false;
            // Stopping releases the old endpoint epoch. A node switch often replaces the core at the same port.
            await PrepareCoreAsync();
        }
        catch (Exception ex) { _error = ProxyTunSession.SafeCode(ex); _proxyReady = false; Phase = UserTransportPhase.Error; Add("ОШИБКА", Explain(_error) + " Код: " + _error); }
        _nextPrepare = DateTimeOffset.UtcNow.AddSeconds(_proxyReady ? 45 : 15);
    }
    public async Task PulseAsync()
    {
        if (!await _gate.WaitAsync(0)) return;
        try
        {
            if (_run is not null)
            {
                Observe(); var e = _run.Read();
                if (e.Failure is not null || Phase == UserTransportPhase.Enabled && !e.Running)
                {
                    _error = e.Failure ?? "TRANSPORT_NOT_RUNNING"; _proxyReady = false; Phase = UserTransportPhase.Error;
                    if (_observedFailure != _error) { _observedFailure = _error; Add("ОШИБКА", Explain(_error) + " Код: " + _error); _nextPrepare = DateTimeOffset.UtcNow.AddSeconds(15); }
                    if (e.Cleanup) { if (e.CoreCreated && e.CoreExited) Add("ИНФО", $"Собственное ядро завершено; код выхода {e.ExitCode?.ToString() ?? "неизвестен"}. Очистка подтверждена."); await SaveReportAsync(); _run = null; }
                }
                if (DateTimeOffset.UtcNow >= _nextSave) { _nextSave = DateTimeOffset.UtcNow.AddSeconds(10); await SaveReportAsync(); }
            }
            if (!NeedsStop && Phase != UserTransportPhase.Enabled && DateTimeOffset.UtcNow >= _nextPrepare) await PrepareCoreAsync();
        }
        finally { _gate.Release(); Notify(); }
    }
    private void Observe()
    {
        if (_run is null) return; var e = _run.Read();
        foreach (var item in e.Lifecycle ?? [])
        {
            string key = item.ElapsedMs + ":" + item.Stage; if (!_events.Add(key)) continue;
            _eventOrder.Enqueue(key); while (_eventOrder.Count > 4096) _events.Remove(_eventOrder.Dequeue());
            string message = item.Stage switch
            {
                "PreflightStarted" => "Начата проверка перед запуском.", "LocalProxyTcpUdpVerified" => "Перед запуском повторно подтверждены TCP и UDP через локальный SOCKS5.",
                "FilePinsAndSignatureVerified" => "Подписи и контрольные суммы клиента и ядра проверены.", "BaselineCaptured" => "Сохранён исходный снимок сетевого состояния.",
                "BaselineReadOnlyStabilityStarted" => "До запуска ядра проверяется стабильность исходной сети; настройки не меняются.",
                "BaselineReadOnlyStable" => "Два последовательных исходных снимка сети совпадают.",
                "BaselineReadOnlyChanging" => "Исходная сеть ещё меняется до запуска нашего ядра. Выполняется последняя ограниченная проверка.",
                "PreviousJournalInspectionStarted" => "Обнаружен журнал предыдущей операции. Начата безопасная проверка собственных ресурсов.", "PreviousJournalSafelyReleased" => "Журнал предыдущей операции безопасно архивирован; чужие настройки не менялись.",
                "ConfigurationCheckPassed" => "Конфигурация принята ядром.", "CoreProcessCreatedAndResumed" => "Собственный процесс ядра создан и запущен.",
                "LocalApiReady" => "Локальный API ядра доступен.", "TunAdapterObserved" => "Собственный сетевой адаптер обнаружен.",
                "TransportReadyForGame" => "Запуск транспорта и изоляция сетевых изменений подтверждены.", "CoreLocalProxyEstablished" => "Соединение ядра с локальным прокси установлено.",
                "LocalProxyHealthTcpUdpPassed" => "Фоновая проверка прокси: TCP и UDP доступны.", "ControllerSafetyStopRequested" => "Потеря доступности или нарушение проверки: запрошена безопасная остановка.",
                "CleanupStarted" => "Начата очистка собственных ресурсов.", "CoreAlreadyExited" => "Ядро уже завершилось до команды остановки.",
                "CleanupConfirmed" => "Освобождение собственных ресурсов подтверждено.", "CleanupNotConfirmed" => "Очистка не подтверждена; повторный запуск заблокирован.",
                "CleanupOwnedResourcesConfirmed_ExternalStateChanged" => "Собственные ресурсы освобождены; изменение внешнего состояния сети сохранено отдельно, возврат всей сети к старому снимку не заявляется.",
                "AttemptAbortedNoOwnedCore" => "Новое ядро не создавалось; освобождать ресурсы новой попытки не требуется. Это не подтверждение восстановления старого журнала.",
                _ => "Событие транспорта: " + item.Stage
            };
            Log.Add(item.Stage.Contains("Rejected") || item.Stage.Contains("NotConfirmed") ? "ОШИБКА" : "ИНФО", message, item.Utc);
        }
        var checks = e.StartupIsolation ?? [];
        foreach (var check in checks.Skip(_isolationLogged))
        {
            foreach (var predicate in check.Predicates.Where(p => !p.Passed || p.ReasonCode != "PASSED"))
            {
                Add(predicate.Passed ? "ИНФО" : "ВНИМАНИЕ", $"Проверка изоляции №{check.Snapshot}: {predicate.Id}; {predicate.ReasonCode}.");
                foreach (var field in predicate.Differences.Take(4))
                    Add(predicate.Passed ? "ИНФО" : "ВНИМАНИЕ", $"{field.Row}, {field.Field}: до={field.Expected}; после={field.Observed}.");
            }
            if (check.TeredoTransitions is { Count: > 0 })
                Add("ИНФО", "Распознан автоматический lifecycle Teredo по системному типу и идентичности, без назначенных DNS-серверов. Его состояние учитывается отдельно от ресурсов нашего TUN.");
        }
        _isolationLogged = checks.Count;
        if (!_startupProbeLogged && e.StartupProxyProbe is not null && _prepared is not null)
        { _startupProbeLogged = true; LocalTransportPlatform.ProbeLog(Add, _prepared.Proxy.Port, e.StartupProxyProbe); }
        if (!_gameLogged && e.GameObserved) { _gameLogged = true; Add("ИНФО", "Обнаружено соединение проверенного Aion; применено сохранённое игровое правило."); }
        if (!_discordLogged && e.DiscordObserved) { _discordLogged = true; Add("ИНФО", "Обнаружен UDP проверенного Discord; применено сохранённое правило передачи через прокси."); }
        if (e.Discord is not null)
        {
            var media = JsonSerializer.SerializeToNode(e.Discord); var probe = media?["UdpChainProbe"];
            string? key = (string?)probe?["Utc"];
            if (key is not null && key != _lastUdpProof)
            {
                _lastUdpProof = key;
                bool passed = (bool?)probe?["Passed"] == true;
                Add(passed ? "ИНФО" : "ВНИМАНИЕ", passed ? "Фоновая контрольная UDP-передача через общий прокси: ответ датаграммы подтверждён." : "Фоновая контрольная UDP-передача не подтверждена: " + ((string?)probe?["Failure"] ?? "неизвестная ошибка") + ". Маршрут автоматически не переключался.");
            }
        }
    }
    private async Task SaveReportAsync()
    {
        if (!_persist || _run is null || _report is null || _save is { IsCompleted: false }) return;
        var e = _run.Read(); string report = _report;
        var value = new { Product = Product.Name, Version = Product.Version, UpdatedUtc = DateTimeOffset.UtcNow, Mode = "CombinedAionDiscord", Session = e.Native,
            Discord = e.Discord, ConfigurationSHA256 = e.ConfigurationSha256, UserGameVerificationForThisRelease = false };
        _save = Task.Run(() =>
        {
            try { string dir = Path.Combine(ProxyTunPlan.Root, "Reports"); TunPrivateStore.EnsurePrivate(dir); string file = Path.Combine(dir, "safe-report-" + report + ".json"); string temp = file + ".tmp"; File.WriteAllText(temp, JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = true })); File.Move(temp, file, true); }
            catch { Add("ОШИБКА", "Не удалось сохранить автоматический отчёт. Проверьте доступ к локальному хранилищу."); }
        }); await _save;
    }
    private async Task SaveReadinessAsync()
    {
        if (!_persist) return;
        _readinessHistory.Enqueue(new { Utc = DateTimeOffset.UtcNow, Phase = Phase.ToString(), Failure = _error,
            ProxyPort = _prepared?.Proxy.Port, EndpointIdentitySha256 = _prepared is null ? null : ProxyEndpointRefresh.Identity(_prepared.Proxy),
            PreparationProbe = _platform.LastProbe, StartupProbe = _run?.Read().StartupProxyProbe, NativeFailure = _run?.Read().Failure });
        while (_readinessHistory.Count > 32) _readinessHistory.Dequeue();
        var history = _readinessHistory.ToArray();
        await Task.Run(() =>
        {
            try
            {
                string dir = Path.Combine(ProxyTunPlan.Root, "Reports"); TunPrivateStore.EnsurePrivate(dir);
                string file = Path.Combine(dir, "safe-readiness-" + _readinessReport + ".json");
                File.WriteAllText(file + ".tmp", JsonSerializer.Serialize(new { Product = Product.Name, Version = Product.Version,
                    Kind = "BoundedReadinessHistory", NativeTransportStartedByThisRecorder = false, Captures = history }, new JsonSerializerOptions { WriteIndented = true }));
                File.Move(file + ".tmp", file, true);
            }
            catch { Add("ВНИМАНИЕ", "Не удалось сохранить историю проверок готовности. Транспорт автоматически не включался."); }
        });
    }
    public async Task CloseAsync()
    {
        await _gate.WaitAsync();
        try { if (_run is not null) await StopCoreAsync(false); }
        finally { _gate.Release(); Notify(); }
    }
    public static string Explain(string code) => code switch
    {
        "PROXY_NOT_FOUND" => "V2rayN не найден или его TUN включён. Запустите V2rayN, выключите только его TUN; проверка повторится автоматически.",
        "PROXY_MULTIPLE_CLIENTS" => "Найдено несколько клиентов V2rayN. Оставьте нужный клиент; проверка повторится автоматически.",
        "PROXY_AUTH_REQUIRED" => "Вход V2rayN требует пароль. Нужен локальный SOCKS5-вход без авторизации.",
        "PROXY_RESPONSE_TIMEOUT" or "PROXY_UPSTREAM_UNRESPONSIVE" => "Прокси не подтвердил передачу данных. Проверьте подключение V2rayN; доступность будет проверена повторно.",
        "PROXY_TCP_RESPONSE_TIMEOUT" => "Не получен контрольный TCP-ответ через прокси. В журнале указан этап и обе использованные контрольные цели; UDP проверяется независимо.",
        "PROXY_UDP_RESPONSE_TIMEOUT" => "Не получен контрольный UDP-ответ через прокси. Успешный TCP не заменяет UDP; этап и контрольные цели сохранены в журнале.",
        "PROXY_LOCAL_SOCKET_UNAVAILABLE" => "Локальный вход V2rayN больше не принимает соединения. Выполняется повторное обнаружение текущего порта; старые параметры не используются для нового запуска.",
        "PROXY_UDP_ASSOCIATE_REJECTED" or "PROXY_UDP_RESPONSE_INVALID" or "DISCORD_UDP_CHAIN_NOT_VERIFIED" => "Не подтверждена передача UDP через прокси. Проверьте доступность выбранного подключения V2rayN.",
        "AION_STEAM_NOT_FOUND" => "Установка Aion не найдена. Проверьте её наличие в Steam; запускать игру для подготовки не нужно.",
        "DISCORD_SIGNED_CLIENT_NOT_FOUND" => "Подписанный клиент Discord не найден. Проверьте установку обычного Discord.",
        "AION_SIGNATURE_NOT_TRUSTED" or "TUN_AION_SIGNATURE_UNTRUSTED" => "Подпись клиента игры не прошла проверку. Проверьте файлы игры в Steam.",
        "AION_UPDATED_RECHECK_REQUIRED" or "DISCORD_UPDATED_RECHECK_REQUIRED" or "TUN_AION_IMAGE_CHANGED" => "Приложение обновилось. Подождите автоматической повторной проверки перед включением.",
        "TUN_CORE_HASH_CHANGED" => "Файлы транспорта отличаются от проверенного комплекта. Распакуйте выпуск заново в отдельную папку.",
        "TUN_CORE_CHECK_REJECTED" => "Ядро не приняло конфигурацию. Проверьте целостность комплекта и сведения в журнале.",
        "TUN_CORE_EXITED_BEFORE_API" or "TUN_CORE_API_NOT_READY" => "Ядро не подтвердило запуск. Оно остановлено; сведения о завершении сохранены в журнале и автоматическом отчёте.",
        "V2RAY_EXITED" or "PROXY_OWNER_CHANGED" or "PROXY_LISTENER_GONE" or "PROXY_CONFIGURATION_CHANGED" => "V2rayN или его ядро перезапущены либо изменены. Транспорт остановлен; проверьте V2rayN и дождитесь подготовки.",
        "TUN_PREFLIGHT_CONFLICT" => "Обнаружен работающий клиент игры или другой сетевой обработчик. Включите транспорт перед следующим запуском игры; программы не останавливались.",
        "TUN_EXISTING_TUN_OR_DEFAULT_NOT_PHYSICAL" => "Обнаружен другой TUN. Выключите его вручную, оставив V2rayN работающим.",
        "TUN_NON_TUN_DNS_CHANGED" => "Запуск заблокирован: изменились DNS-строки другого интерфейса (исчезновение строки не означает замену DNS-сервера). Контекст и сравнение сохранены в автоматическом отчёте.",
        "TUN_NON_TUN_INTERFACE_CHANGED" => "Запуск заблокирован: во время включения изменились параметры другого сетевого интерфейса. Конкретное поле сохранено в журнале и автоматическом отчёте.",
        "TUN_NON_TUN_ADAPTER_CHANGED" or "TUN_NON_TUN_ADDRESS_CHANGED" or "TUN_NON_TUN_ROUTE_CHANGED" => "Запуск заблокирован: изменились сторонние адаптеры, адреса или маршруты. Точная категория и различия сохранены в StartupIsolation; сеть не исправлялась автоматически.",
        "TUN_TEREDO_RESTORATION_NOT_CONFIRMED" => "Ядро остановлено, но возврат служебного Teredo к исходному состоянию ещё не подтверждён. Повторное включение заблокировано; сохраните отчёт, не удаляйте marker и не сбрасывайте сеть.",
        "TUN_SYSTEM_PROXY_CHANGED" => "Запуск заблокирован: во время включения изменился системный прокси. Его настройки программа не меняла; сравнение сохранено в отчёте.",
        "TUN_FIREWALL_PROFILES_CHANGED" => "Запуск заблокирован: изменились настройки профиля Firewall. Защита не отключалась; сравнение сохранено в отчёте.",
        "TUN_LOCAL_PROXY_ROUTE_NOT_EXCLUDED" => "Запуск заблокирован: маршрут TUN охватывает локальный прокси. Соединение не признано готовым; причина сохранена в отчёте.",
        "TUN_OWN_INDEX_NOT_NEW_AT_START" => "Запуск заблокирован: индекс нового адаптера совпал с исходным интерфейсом. Безопасная изоляция не подтверждена.",
        "TUN_ROUTING_DNS_ISOLATION_FAILED" => "Запуск заблокирован проверкой изоляции сети. Это не ошибка проверки SOCKS5; сведения сохранены в автоматическом отчёте.",
        "TUN_CORE_EXITED_DURING_ISOLATION" => "Ядро завершилось во время проверки изоляции сети. Запуск не признан успешным; сведения об остановке сохранены в отчёте.",
        "TUN_BASELINE_NOT_SETTLED" => "До запуска нашего ядра меняется исходное состояние сети. TUN не создавался; сведения о различиях сохранены. Дождитесь завершения переключения V2rayN и нажмите «Включить» после подготовки.",
        "TUN_OWNER_STILL_ALIVE_STOP_IN_WINDOW" => "Предыдущая программа ещё работает. Используйте её окно; принудительная остановка не выполнялась.",
        "TUN_OWN_RESOURCES_NOT_RELEASED" or "TUN_BASELINE_AFTER_MISMATCH" => "Очистка не подтверждена. Нажмите «Выключить» для повторной штатной остановки; новые подключения заблокированы.",
        "TUN_START_ISOLATION_NOT_PROVEN" => "Изоляция предыдущей операции и итоговое состояние сети не подтверждены. Новый запуск заблокирован. Отправьте safe-recovery из папки отчётов; сбрасывать сеть или удалять marker вручную не нужно.",
        "TUN_OWNERSHIP_NOT_PROVEN" or "TUN_RECOVERY_MUTATION_SCOPE_UNVERIFIED" => "Нельзя безопасно завершить старый журнал: не подтверждены принадлежность ресурсов или границы старой конфигурации. Повторный запуск заблокирован. Передайте safe-recovery; файлы и сетевые настройки не удаляйте.",
        "TUN_OWN_GUID_REMAINS" or "TUN_OWN_ROUTE_SIGNATURE_REMAINS" or "TUN_OWN_NEXT_HOP_REMAINS" or "TUN_OWN_ADAPTER_REMAINS" or "TUN_OWN_ADDRESS_REMAINS" or "TUN_OWN_RANGE_ROUTE_REMAINS" => "Ядро остановлено, но обнаружен остаток собственного адаптера, адреса или маршрута. Новое включение заблокировано; повторите штатную остановку и сохраните отчёт.",
        "TUN_RECOVERY_CORE_STILL_PRESENT" => "Найдено ещё работающее ядро. Закройте его программу штатно; чужие процессы принудительно не останавливаются.",
        _ when code.StartsWith("TUN_OWN_INDEX_REMAINS_", StringComparison.Ordinal) => "В сети ещё виден ресурс собственного интерфейса. Новое включение заблокировано; повторите штатную остановку и сохраните отчёт.",
        _ => "Действие не выполнено (" + code + "). Проверьте V2rayN и сведения в журнале; автоматическая проверка будет повторена."
    };
}
