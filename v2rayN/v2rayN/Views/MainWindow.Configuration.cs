namespace v2rayN.Views;

public partial class MainWindow
{
    private static readonly CultureInfo ConfigurationCulture = CultureInfo.GetCultureInfo("ru-RU");
    private int _configurationRefresh;

    private async Task RefreshConfigurationSummaryAsync()
    {
        var refresh = ++_configurationRefresh;
        var manager = AppManager.Instance;
        var selected = nodeList.SelectedItem as ProfileItemModel;
        var id = selected?.Subid ?? _config.SubIndexId;
        SubItem? item = null;
        try
        {
            if (manager.ConnectionModes?.ConnectedNodeId is { } connectedId)
            {
                id = (await manager.GetProfileItem(connectedId))?.Subid;
            }
            if (!string.IsNullOrEmpty(id))
            {
                item = await manager.GetSubItem(id);
            }
            else if (selected is null && manager.ConnectionModes?.ConnectedNodeId is null)
            {
                var configurations = (await manager.SubItems() ?? []).Where(sub => sub.Enabled &&
                    (sub.VaKoLinkExpiresAt.HasValue || sub.VaKoLinkUsedBytes.HasValue)).Take(2).ToArray();
                item = configurations is [var only] ? only : null;
            }
        }
        catch (Exception error)
        {
            Logging.SaveLog("Чтение срока и трафика конфигурации", error);
        }
        if (refresh == _configurationRefresh)
        {
            RenderConfigurationSummary(item, DateTimeOffset.Now);
        }
    }

    private void RenderConfigurationSummary(SubItem? item, DateTimeOffset now)
    {
        configurationStatus.Text = "Статус конфигурации недоступен";
        configurationExpiry.Text = "Срок конфигурации недоступен";
        if (item?.VaKoLinkExpiresAt is > 0 and <= 253402300799)
        {
            var expires = DateTimeOffset.FromUnixTimeSeconds(item.VaKoLinkExpiresAt.Value).ToLocalTime();
            var days = Math.Max(0, (expires.Date - now.Date).Days);
            configurationStatus.Text = expires <= now ? "Срок конфигурации истёк" : "Конфигурация активна";
            var date = expires.ToString("d MMMM yyyy", ConfigurationCulture);
            configurationExpiry.Text = expires <= now ? $"Действовала до {date}"
                : $"Действует до {date} — осталось {days} {ConfigurationDays(days)}";
        }

        configurationTraffic.Text = item?.VaKoLinkUsedBytes is { } used
            ? item.VaKoLinkTotalBytes switch
            {
                0 => $"Общий трафик конфигурации {ConfigurationGigabytes(used)} ГБ — без лимита",
                { } limit => $"Общий трафик конфигурации {ConfigurationGigabytes(used)} из {ConfigurationGigabytes(limit)} ГБ",
                null => $"Общий трафик конфигурации {ConfigurationGigabytes(used)} ГБ — лимит недоступен"
            }
            : "Данные о трафике конфигурации недоступны";
    }

    private static string ConfigurationDays(int days) => (days % 100) is >= 11 and <= 14 ? "дней"
        : (days % 10) switch { 1 => "день", 2 or 3 or 4 => "дня", _ => "дней" };

    private static string ConfigurationGigabytes(long bytes) =>
        (bytes / 1073741824m).ToString("0.##", ConfigurationCulture);
}
