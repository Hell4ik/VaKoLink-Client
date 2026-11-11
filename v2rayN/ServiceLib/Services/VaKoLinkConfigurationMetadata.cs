using System.Collections.Concurrent;

namespace ServiceLib.Services;

public static class VaKoLinkConfigurationMetadata
{
    public enum Scope { Traffic, Expiry, All }

    private static readonly ConcurrentDictionary<(string, Scope), string> Failures = new();

    public static bool Supports(SubItem item) =>
        string.IsNullOrWhiteSpace(item.ConvertTarget) && TryGetPortalUri(item, out _);

    public static string? GetFailure(string id, Scope scope) => Failures.GetValueOrDefault((id, scope));

    public static async Task RefreshAsync(SubItem item, Scope scope)
    {
        try
        {
            if (!Supports(item) || !TryGetPortalUri(item, out var uri))
            {
                return;
            }
            if (!HttpRequestHeadersHelper.TryParse(item.RequestHeaders, out var headers))
            {
                throw new FormatException();
            }

            var downloader = new DownloadService { RequestHeaders = headers };
            VaKoLinkConfigurationUsage? usage = null;
            await downloader.DownloadVaKoLinkSubscriptionAsync(uri!, false, item.UserAgent,
                receiveUsage: value => usage = value, metadataOnly: true);
            await SaveAsync(item, usage!, scope);
        }
        catch (Exception error)
        {
            var method = error.TargetSite?.DeclaringType?.Name;
            Logging.SaveLog($"Проверка данных конфигурации ({scope}): {method} · {error.GetType().Name} · 0x{error.HResult:X8}");
            ReportFailure(item, scope, error);
        }
    }

    private static bool TryGetPortalUri(SubItem item, out Uri? uri) =>
        Uri.TryCreate(item.Url?.Trim(), UriKind.Absolute, out uri) && VaKoLinkSubscription.IsPortalUri(uri);

    internal static async Task SaveAsync(SubItem item, VaKoLinkConfigurationUsage usage, Scope scope)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        const string where = " WHERE Id = ? AND Url = ? AND coalesce(ConvertTarget, '') = ''";
        var database = SQLiteHelper.Instance;
        switch (scope)
        {
            case Scope.Traffic:
                await database.ExecuteAsync(
                    "UPDATE SubItem SET VaKoLinkUsedBytes = ?, VaKoLinkTotalBytes = ?, VaKoLinkTrafficCheckedAt = ?" + where,
                    usage.UsedBytes, usage.TotalBytes, now, item.Id, item.Url);
                break;
            case Scope.Expiry:
                await database.ExecuteAsync(
                    "UPDATE SubItem SET VaKoLinkExpiresAt = ?, VaKoLinkExpiryCheckedAt = ?" + where,
                    usage.ExpiresAt, now, item.Id, item.Url);
                break;
            default:
                await database.ExecuteAsync(
                    "UPDATE SubItem SET VaKoLinkExpiresAt = ?, VaKoLinkUsedBytes = ?, VaKoLinkTotalBytes = ?, " +
                    "VaKoLinkTrafficCheckedAt = ?, VaKoLinkExpiryCheckedAt = ?" + where,
                    usage.ExpiresAt, usage.UsedBytes, usage.TotalBytes, now, now, item.Id, item.Url);
                break;
        }
        SetFailure(item.Id, scope, null);
    }

    internal static void ReportFailure(SubItem item, Scope scope, Exception? error = null)
    {
        var message = error switch
        {
            VaKoLinkSubscriptionException { Message: VaKoLinkSubscription.PendingMessage } => "Устройство ожидает одобрения",
            VaKoLinkSubscriptionException { StatusCode: { } code } => $"Ошибка портала · HTTP {(int)code}",
            HttpRequestException { StatusCode: { } code } => $"Ошибка портала · HTTP {(int)code}",
            OperationCanceledException => "Истекло время ожидания ответа портала",
            FormatException => "Некорректные HTTP-заголовки конфигурации",
            _ => "Не удалось обновить данные конфигурации"
        };
        SetFailure(item.Id, scope, message);
    }

    private static void SetFailure(string id, Scope scope, string? message)
    {
        if (scope != Scope.Expiry)
        {
            Set(Scope.Traffic);
        }
        if (scope != Scope.Traffic)
        {
            Set(Scope.Expiry);
        }
        AppEvents.VaKoLinkConfigurationUsageChanged.Publish(id);

        void Set(Scope field)
        {
            if (message is null)
            {
                Failures.TryRemove((id, field), out _);
            }
            else
            {
                Failures[(id, field)] = message;
            }
        }
    }
}
