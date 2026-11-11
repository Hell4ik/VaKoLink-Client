namespace ServiceLib.Services;

internal sealed class VaKoLinkSubscriptionException(string message, HttpStatusCode? statusCode = null) : Exception(message)
{
    internal HttpStatusCode? StatusCode { get; } = statusCode;
}

internal static class VaKoLinkSubscription
{
    internal const string PendingMessage = "Устройство ожидает одобрения. После одобрения обновите подписку";
    private const string RequiresHwid = "Enable HWID in the subscription settings";
    private const string AwaitsApproval = "Device awaits administrator approval";
    private const string HwidHeader = "x-hwid";
    private const string DeviceOsHeader = "x-device-os";
    private const int MaxRedirects = 10;

    internal static bool IsPortalUri(Uri uri) =>
        uri.IsAbsoluteUri && uri.Scheme == Uri.UriSchemeHttps && uri.IsDefaultPort && uri.UserInfo.Length == 0 &&
        uri.IdnHost.Equals("access.vakolink.com", StringComparison.OrdinalIgnoreCase);

    internal static bool IsPortalSubscription(Uri uri) =>
        IsPortalUri(uri) && uri.AbsolutePath.StartsWith("/s/", StringComparison.Ordinal) && uri.AbsolutePath.Length > 3;

    internal static async Task<string> DownloadAsync(HttpClient client, Uri uri, IReadOnlyDictionary<string, string> headers,
        Func<string> getDeviceId, CancellationToken cancellationToken, Action<VaKoLinkConfigurationUsage>? receiveUsage = null,
        bool metadataOnly = false)
    {
        var manual = headers.GetValueOrDefault(HwidHeader);
        var hwid = string.IsNullOrWhiteSpace(manual) ? null : manual;
        var deviceOs = hwid is not null && headers.GetValueOrDefault(DeviceOsHeader) is { Length: > 0 } configuredOs
            ? configuredOs
            : "Windows";
        for (var attempt = 0; ; attempt++)
        {
            var (response, trusted, portal) = await SendAsync(client, uri, headers, hwid, deviceOs, cancellationToken, metadataOnly);
            using (response)
            {
                if (response.IsSuccessStatusCode)
                {
                    var content = metadataOnly ? string.Empty : await response.Content.ReadAsStringAsync(cancellationToken);
                    if (receiveUsage is not null)
                    {
                        receiveUsage(VaKoLinkConfigurationUsage.Parse(
                            portal && response.Headers.TryGetValues("Subscription-Userinfo", out var values) ? values : []));
                    }
                    return content;
                }

                if (trusted && response.StatusCode == HttpStatusCode.Forbidden &&
                    string.Equals(response.Content.Headers.ContentType?.MediaType, "text/plain", StringComparison.OrdinalIgnoreCase))
                {
                    var message = await ReadPortalErrorAsync(response.Content, cancellationToken);
                    if (message == AwaitsApproval)
                    {
                        throw new VaKoLinkSubscriptionException(PendingMessage, response.StatusCode);
                    }
                    if (message == RequiresHwid)
                    {
                        if (attempt != 0 || hwid is not null)
                        {
                            throw new VaKoLinkSubscriptionException("Портал требует HWID и не принял отправленный идентификатор.", response.StatusCode);
                        }
                        hwid = getDeviceId();
                        continue;
                    }
                }

                throw new VaKoLinkSubscriptionException($"Не удалось получить подписку. HTTP {(int)response.StatusCode}.", response.StatusCode);
            }
        }
    }

    private static async Task<(HttpResponseMessage Response, bool Trusted, bool Portal)> SendAsync(HttpClient client, Uri uri,
        IReadOnlyDictionary<string, string> headers, string? hwid, string deviceOs, CancellationToken cancellationToken,
        bool metadataOnly)
    {
        var trusted = IsPortalSubscription(uri);
        var portal = IsPortalUri(uri);
        var sameOrigin = true;
        for (var redirects = 0; ; redirects++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            var requestHeaders = new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase);
            requestHeaders.Remove("Host");
            requestHeaders.Remove(HwidHeader);
            requestHeaders.Remove(DeviceOsHeader);
            if (!sameOrigin)
            {
                requestHeaders.Remove("Authorization");
                requestHeaders.Remove("Cookie");
            }
            if (trusted && hwid is not null)
            {
                requestHeaders[HwidHeader] = hwid;
                requestHeaders[DeviceOsHeader] = deviceOs;
            }
            HttpRequestHeadersHelper.Apply(request, requestHeaders);

            var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (response.StatusCode is not (HttpStatusCode.MovedPermanently or HttpStatusCode.Found or HttpStatusCode.SeeOther
                or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect) || response.Headers.Location is not { } location)
            {
                return (response, trusted, portal);
            }
            response.Dispose();
            if (redirects >= MaxRedirects || !Uri.TryCreate(uri, location, out var next) ||
                next.Scheme != Uri.UriSchemeHttps || next.UserInfo.Length != 0 ||
                (metadataOnly && !IsPortalUri(next)))
            {
                throw new VaKoLinkSubscriptionException("Портал вернул недопустимое перенаправление подписки.");
            }
            sameOrigin &= uri.IdnHost.Equals(next.IdnHost, StringComparison.OrdinalIgnoreCase) && uri.Port == next.Port;
            trusted &= IsPortalSubscription(next);
            portal &= IsPortalUri(next);
            uri = next;
        }
    }

    private static async Task<string?> ReadPortalErrorAsync(HttpContent content, CancellationToken cancellationToken)
    {
        // The portal's plain-text responses are short. Do not download or display arbitrary error bodies.
        using var reader = new StreamReader(await content.ReadAsStreamAsync(cancellationToken));
        var buffer = new char[256];
        var length = await reader.ReadBlockAsync(buffer.AsMemory(), cancellationToken);
        return length < buffer.Length ? new string(buffer, 0, length).Trim() : null;
    }

    internal static string GetOrCreateDeviceId(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                var id = Guid.NewGuid().ToString("N");
                var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
                try
                {
                    using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        stream.Write(Encoding.ASCII.GetBytes(id));
                        stream.Flush(flushToDisk: true);
                    }
                    // Concurrent updates use the first successfully saved ID.
                    File.Move(temporary, path);
                }
                catch (IOException) when (File.Exists(path))
                {
                }
                finally
                {
                    File.Delete(temporary);
                }
            }

            var saved = File.ReadAllText(path);
            if (Guid.TryParseExact(saved, "N", out _))
            {
                return saved;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new VaKoLinkSubscriptionException("Не удалось сохранить или прочитать идентификатор устройства.");
        }
        throw new VaKoLinkSubscriptionException("Сохранённый идентификатор устройства повреждён.");
    }
}
