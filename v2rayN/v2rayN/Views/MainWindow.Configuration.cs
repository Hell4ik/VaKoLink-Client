namespace v2rayN.Views;

public partial class MainWindow
{
    private static readonly CultureInfo ConfigurationCulture = CultureInfo.GetCultureInfo("ru-RU");
    private static readonly TimeZoneInfo ConfigurationTimeZone = TimeZoneInfo.FindSystemTimeZoneById("Ekaterinburg Standard Time");
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
                    (sub.VaKoLinkExpiresAt.HasValue || sub.VaKoLinkUsedBytes.HasValue ||
                     sub.VaKoLinkTotalBytes.HasValue)).Take(2).ToArray();
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
        configurationStatus.Text = "Статус конфигурации — Нет данных";
        configurationExpiry.Text = "Срок конфигурации — Нет данных";
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

        var used = item?.VaKoLinkUsedBytes is { } usedBytes ? ConfigurationGigabytes(usedBytes) : null;
        const string traffic = "Общий трафик конфигурации";
        configurationTraffic.Text = (used, item?.VaKoLinkTotalBytes) switch
        {
            ({ } amount, 0) => $"{traffic} {amount} ГБ — без лимита",
            ({ } amount, { } limit) => $"{traffic} {amount} из {ConfigurationGigabytes(limit)} ГБ",
            ({ } amount, null) => $"{traffic} {amount} ГБ, лимит — Нет данных",
            (null, 0) => $"{traffic} — Нет данных, без лимита",
            (null, { } limit) => $"{traffic} — Нет данных из {ConfigurationGigabytes(limit)} ГБ",
            _ => $"{traffic} — Нет данных"
        };
    }

    private static string ConfigurationDays(int days) => (days % 100) is >= 11 and <= 14 ? "дней"
        : (days % 10) switch { 1 => "день", 2 or 3 or 4 => "дня", _ => "дней" };

    private static string ConfigurationGigabytes(long bytes) =>
        (bytes / 1073741824m).ToString("0.##", ConfigurationCulture);
}
