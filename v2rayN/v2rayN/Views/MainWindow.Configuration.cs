using System.Windows.Threading;
using ServiceLib.Services;
using static ServiceLib.Services.VaKoLinkConfigurationMetadata;
using Scope = ServiceLib.Services.VaKoLinkConfigurationMetadata.Scope;

namespace v2rayN.Views;

public partial class MainWindow
{
    private static readonly CultureInfo ConfigurationCulture = CultureInfo.GetCultureInfo("ru-RU");
    private static readonly TimeZoneInfo ConfigurationTimeZone = TimeZoneInfo.FindSystemTimeZoneById("Ekaterinburg Standard Time");
    private int _configurationRefresh;
    private SubItem? _configurationSummary;
    private bool _refreshingTraffic;
    private DateOnly? _expiryCheckDay;
    private bool _checkingExpiry;

    private void BindConfigurationControls()
    {
        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        timer.Tick += async (_, _) => await RefreshDailyExpiryAsync();
        Loaded += async (_, _) =>
        {
            timer.Start();
            await RefreshConfigurationSummaryAsync();
            await RefreshDailyExpiryAsync();
        };
        Closed += (_, _) => timer.Stop();
        refreshTrafficButton.Click += async (_, _) =>
        {
            if (_refreshingTraffic || _configurationSummary is not { } item || !Supports(item))
            {
                return;
            }
            _refreshingTraffic = true;
            RenderTrafficSummary(item);
            try
            {
                await RefreshAsync(item, Scope.Traffic);
            }
            finally
            {
                _refreshingTraffic = false;
                await RefreshConfigurationSummaryAsync();
            }
        };
    }

    private async Task RefreshDailyExpiryAsync()
    {
        var day = ConfigurationDay(DateTimeOffset.UtcNow);
        if (AppManager.Instance.ConnectionModes is not { Ready: true } || _checkingExpiry || _expiryCheckDay == day)
        {
            return;
        }
        _checkingExpiry = true;
        try
        {
            await RefreshConfigurationSummaryAsync();
            var items = await AppManager.Instance.SubItems() ?? [];
            _expiryCheckDay = day;
            foreach (var item in items.Where(item => item.Enabled && Supports(item) &&
                (item.VaKoLinkExpiryCheckedAt is not { } checkedAt ||
                 ConfigurationDay(DateTimeOffset.FromUnixTimeSeconds(checkedAt)) < day)))
            {
                await RefreshAsync(item, Scope.Expiry);
            }
        }
        catch (Exception error)
        {
            Logging.SaveLog("Ежедневное обновление срока конфигурации", error);
        }
        finally
        {
            _checkingExpiry = false;
        }
    }

    private static DateOnly ConfigurationDay(DateTimeOffset value) =>
        DateOnly.FromDateTime(TimeZoneInfo.ConvertTime(value, ConfigurationTimeZone).Date);

    private async Task RefreshConfigurationSummaryAsync()
    {
        var refresh = ++_configurationRefresh;
        var manager = AppManager.Instance;
        var selected = nodeList.SelectedItem as ProfileItemModel;
        var id = selected?.Subid ?? _config.SubIndexId;
        SubItem? item = null;
        try
        {
            if (manager.ConnectionModes is { IsConnected: true } connection)
            {
                id = connection.ConnectedSubscriptionId;
            }
            if (!string.IsNullOrEmpty(id))
            {
                item = await manager.GetSubItem(id);
            }
            else if (selected is null && manager.ConnectionModes is not { IsConnected: true })
            {
                var configurations = (await manager.SubItems() ?? []).Where(sub => sub.Enabled && Supports(sub)).Take(2).ToArray();
                item = configurations is [var only] ? only : null;
            }
        }
        catch (Exception error)
        {
            Logging.SaveLog("Чтение срока и трафика конфигурации", error);
        }
        if (refresh == _configurationRefresh)
        {
            _configurationSummary = item;
            RenderConfigurationSummary(item, DateTimeOffset.Now);
        }
    }

    private void RenderConfigurationSummary(SubItem? item, DateTimeOffset now)
    {
        var expiryFailure = item is null ? null : GetFailure(item.Id, Scope.Expiry);
        configurationStatus.Text = expiryFailure ?? (item?.VaKoLinkExpiryCheckedAt is null
            ? "Срок конфигурации ещё не обновлялся" : "Портал не передал срок конфигурации");
        configurationExpiry.Text = string.Empty;
        if (item?.VaKoLinkExpiresAt is 0)
        {
            configurationStatus.Text = "Конфигурация активна";
            configurationExpiry.Text = "Дата окончания не задана";
        }
        else if (item?.VaKoLinkExpiresAt is > 0 and <= 253402300799)
        {
            var expires = TimeZoneInfo.ConvertTime(DateTimeOffset.FromUnixTimeSeconds(item.VaKoLinkExpiresAt.Value), ConfigurationTimeZone);
            var today = TimeZoneInfo.ConvertTime(now, ConfigurationTimeZone).Date;
            var days = Math.Max(0, (expires.Date - today).Days);
            configurationStatus.Text = expires <= now ? "Срок конфигурации истёк" : "Конфигурация активна";
            var date = expires.ToString("d MMMM yyyy", ConfigurationCulture);
            configurationExpiry.Text = expires <= now ? $"Действовала до {date}"
                : $"Действует до {date} — осталось {days} {ConfigurationDays(days)}";
        }
        if (expiryFailure is not null && item?.VaKoLinkExpiresAt is not null)
        {
            configurationExpiry.Text += " · срок не обновился";
        }
        if (item is null || !Supports(item))
        {
            configurationStatus.Text = "Срок конфигурации — Нет данных";
            configurationExpiry.Text = string.Empty;
        }
        RenderTrafficSummary(item);
    }

    private void RenderTrafficSummary(SubItem? item)
    {
        var available = item is { Enabled: true } && Supports(item);
        var failure = item is null ? null : GetFailure(item.Id, Scope.Traffic);
        var used = item?.VaKoLinkUsedBytes;
        var limit = item?.VaKoLinkTotalBytes;
        trafficUsed.Text = used is { } bytes ? ConfigurationGigabytes(bytes) : "Нет данных";
        trafficLimit.Text = (used, limit) switch
        {
            ({ }, 0) => " ГБ · без лимита",
            (null, 0) => " · без лимита",
            (null, { } total) => $" · лимит {ConfigurationGigabytes(total)} ГБ",
            ({ }, { } total) => $" из {ConfigurationGigabytes(total)} ГБ",
            ({ }, null) => " ГБ · лимит неизвестен",
            _ => string.Empty
        };
        trafficMeter.Visibility = used.HasValue && limit is > 0 ? Visibility.Visible : Visibility.Collapsed;
        trafficMeter.Value = used.HasValue && limit is > 0 ? Math.Clamp(100d * used.Value / limit.Value, 0, 100) : 0;
        refreshTrafficButton.IsEnabled = available && !_refreshingTraffic &&
            AppManager.Instance.ConnectionModes is { Ready: true };
        refreshTrafficButton.Content = _refreshingTraffic ? "Обновляем…" : "Обновить расход трафика";

        var freshness = item?.VaKoLinkTrafficCheckedAt is { } checkedAt
            ? FormatTrafficTime(checkedAt) : null;
        trafficFreshness.Text = !available ? string.Empty
            : failure is not null ? (freshness is null ? failure : $"Данные {freshness} · сбой обновления")
            : freshness is null ? "Ещё не обновлялся"
            : used is null && limit is null ? "Портал не передал данные"
            : $"Обновлено {freshness}";
    }

    private static string FormatTrafficTime(long checkedAt)
    {
        var updated = TimeZoneInfo.ConvertTime(DateTimeOffset.FromUnixTimeSeconds(checkedAt), ConfigurationTimeZone);
        return ConfigurationDay(updated) == ConfigurationDay(DateTimeOffset.UtcNow)
            ? $"в {updated:HH:mm}" : updated.ToString("dd.MM HH:mm", ConfigurationCulture);
    }

    private void ShowDiagnostics()
    {
        var item = _configurationSummary;
        var connection = AppManager.Instance.ConnectionModes;
        var configuration = item is null || !Supports(item) ? "Нет конфигурации портала"
            : GetFailure(item.Id, Scope.Traffic) ?? GetFailure(item.Id, Scope.Expiry) ??
              (item.VaKoLinkExpiryCheckedAt is not null || item.VaKoLinkTrafficCheckedAt is not null
                  ? "Ответ портала получен" : "Ещё не проверялась");
        var vpn = connection is { IsConnected: true } ? $"Подключено · {(connection.UseTun ? "TUN" : "Proxy")}"
            : connection is { IsConnecting: true } ? "Подключение…" : "Отключено";
        if (connection?.DiagnosticFailure is { } failure)
        {
            vpn += $" · {failure}";
        }
        var transport = _transport?.DiagnosticFailure ??
            (_transport is { CleanupPending: true } ? "Очистка не подтверждена"
            : _transport is { Busy: true } ? "Выполняется операция"
            : _transport is { IsRunning: true } ? "Работает" : "Остановлен");

        new DiagnosticsWindow(InstalledClientVersion,
            [
                new("Конфигурация", configuration),
                new("Ядро", connection?.IsCoreRunning == true ? "Запущено" : "Остановлено"),
                new("VPN", vpn),
                new("Transport", transport)
            ]) { Owner = this }.ShowDialog();
    }

    private static string ConfigurationDays(int days) => (days % 100) is >= 11 and <= 14 ? "дней"
        : (days % 10) switch { 1 => "день", 2 or 3 or 4 => "дня", _ => "дней" };

    private static string ConfigurationGigabytes(long bytes) =>
        (bytes / 1073741824m).ToString("0.##", ConfigurationCulture);
}
