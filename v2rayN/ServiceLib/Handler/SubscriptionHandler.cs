namespace ServiceLib.Handler;

public static class SubscriptionHandler
{
    private static bool IsVaKoLinkWindows => OperatingSystem.IsWindows() && AppManager.Instance.UseVaKoLinkProfile;

    public static async Task UpdateProcess(Config config, string subId, bool blProxy, Func<bool, string, Task> updateFunc)
    {
        await updateFunc?.Invoke(false, ResUI.MsgUpdateSubscriptionStart);
        var subItem = await AppManager.Instance.SubItems();

        if (subItem is not { Count: > 0 })
        {
            await updateFunc?.Invoke(false, ResUI.MsgNoValidSubscription);
            return;
        }

        var successCount = 0;
        foreach (var item in subItem)
        {
            var hashCode = IsVaKoLinkWindows && item.Remarks?.Contains("://") == true ? "" : $"{item.Remarks}->";
            try
            {
                if (!IsValidSubscription(item, subId))
                {
                    continue;
                }

                if (item.Enabled == false)
                {
                    await updateFunc?.Invoke(false, $"{hashCode}{ResUI.MsgSkipSubscriptionUpdate}");
                    continue;
                }

                // Create download handler
                var downloadHandle = CreateDownloadHandler(item, hashCode, updateFunc);
                await updateFunc?.Invoke(false, $"{hashCode}{ResUI.MsgStartGettingSubscriptions}");

                // Get all subscription content (main subscription + additional subscriptions)
                var result = await DownloadAllSubscriptions(config, item, blProxy, downloadHandle);

                // Process download result
                if (await ProcessDownloadResult(config, item.Id, result, hashCode, updateFunc))
                {
                    successCount++;
                }

                await updateFunc?.Invoke(false, "-------------------------------------------------------");
            }
            catch (VaKoLinkSubscriptionException ex)
            {
                if (IsVaKoLinkWindows && VaKoLinkConfigurationMetadata.Supports(item))
                {
                    VaKoLinkConfigurationMetadata.ReportFailure(item, VaKoLinkConfigurationMetadata.Scope.All, ex);
                }
                NoticeManager.Instance.Enqueue(ex.Message);
                await updateFunc?.Invoke(false, ex.Message);
                await updateFunc?.Invoke(false, "-------------------------------------------------------");
            }
            catch (Exception ex)
            {
                if (IsVaKoLinkWindows)
                {
                    if (VaKoLinkConfigurationMetadata.Supports(item))
                    {
                        VaKoLinkConfigurationMetadata.ReportFailure(item, VaKoLinkConfigurationMetadata.Scope.All, ex);
                    }
                    var message = ex is OperationCanceledException
                        ? "Истекло время ожидания ответа подписки."
                        : ex is FormatException ? ResUI.SubRequestHeadersInvalid : $"Не удалось обновить подписку ({ex.GetType().Name}).";
                    Logging.SaveLog(message);
                    NoticeManager.Instance.Enqueue(message);
                    await updateFunc?.Invoke(false, message);
                }
                else
                {
                    Logging.SaveLog("UpdateSubscription", ex);
                    await updateFunc?.Invoke(false, $"{hashCode}{ResUI.MsgFailedImportSubscription}: {ex.Message}");
                }
                await updateFunc?.Invoke(false, "-------------------------------------------------------");
            }
        }

        await updateFunc?.Invoke(successCount > 0, $"{ResUI.MsgUpdateSubscriptionEnd}");
    }

    private static bool IsValidSubscription(SubItem item, string subId)
    {
        var id = item.Id.TrimEx();
        var url = item.Url.TrimEx();

        if (id.IsNullOrEmpty() || url.IsNullOrEmpty())
        {
            return false;
        }

        if (subId.IsNotEmpty() && item.Id != subId)
        {
            return false;
        }

        if (!url.StartsWith(Global.HttpsProtocol) && !url.StartsWith(Global.HttpProtocol))
        {
            return false;
        }

        return true;
    }

    private static DownloadService CreateDownloadHandler(SubItem item, string hashCode, Func<bool, string, Task> updateFunc)
    {
        if (!HttpRequestHeadersHelper.TryParse(item.RequestHeaders, out var requestHeaders))
        {
            throw new FormatException(ResUI.SubRequestHeadersInvalid);
        }

        var downloadHandle = new DownloadService
        {
            AcceptHeader = "*/*",
            RequestHeaders = requestHeaders,
            RedactStringDownloadErrors = IsVaKoLinkWindows
        };
        downloadHandle.Error += (sender2, args) =>
        {
            updateFunc?.Invoke(false, $"{hashCode}{args.GetException().Message}");
        };
        return downloadHandle;
    }

    private static async Task<string> DownloadSubscriptionContent(DownloadService downloadHandle, string url, bool blProxy,
        string userAgent, bool allowDeviceApproval = true, Action<VaKoLinkConfigurationUsage>? receiveUsage = null)
    {
        if (IsVaKoLinkWindows && allowDeviceApproval && Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
            VaKoLinkSubscription.IsPortalSubscription(uri))
        {
            return await downloadHandle.DownloadVaKoLinkSubscriptionAsync(uri, blProxy, userAgent, receiveUsage);
        }

        var portalUsage = IsVaKoLinkWindows && allowDeviceApproval ? receiveUsage : null;
        var result = await downloadHandle.TryDownloadSubscriptionStringAsync(url, blProxy, userAgent, portalUsage);

        // If download with proxy fails, try direct connection
        if (blProxy && result.IsNullOrEmpty())
        {
            result = await downloadHandle.TryDownloadSubscriptionStringAsync(url, false, userAgent, portalUsage);
        }

        return result ?? string.Empty;
    }

    private static async Task<string> DownloadAllSubscriptions(Config config, SubItem item, bool blProxy, DownloadService downloadHandle)
    {
        // Download main subscription content
        var result = await DownloadMainSubscription(config, item, blProxy, downloadHandle);

        // Process additional subscription links (if any)
        if (item.ConvertTarget.IsNullOrEmpty() && item.MoreUrl.TrimEx().IsNotEmpty())
        {
            result = await DownloadAdditionalSubscriptions(item, result, blProxy, downloadHandle);
        }

        return result;
    }

    private static async Task<string> DownloadMainSubscription(Config config, SubItem item, bool blProxy, DownloadService downloadHandle)
    {
        // Prepare subscription URL and download directly
        var url = Utils.GetPunycode(item.Url.TrimEx());

        // If conversion is needed
        if (item.ConvertTarget.IsNotEmpty())
        {
            var subConvertUrl = config.ConstItem.SubConvertUrl.IsNullOrEmpty()
                ? Global.SubConvertUrls.FirstOrDefault()
                : config.ConstItem.SubConvertUrl;

            url = string.Format(subConvertUrl!, Utils.UrlEncode(url));

            if (!url.Contains("target="))
            {
                url += $"&target={item.ConvertTarget}";
            }

            if (!url.Contains("config="))
            {
                url += $"&config={Global.SubConvertConfig.FirstOrDefault()}";
            }
        }

        // Download and return result directly
        VaKoLinkConfigurationUsage? usage = null;
        var result = await DownloadSubscriptionContent(downloadHandle, url, blProxy, item.UserAgent,
            allowDeviceApproval: item.ConvertTarget.IsNullOrEmpty(), receiveUsage: value => usage = value);
        if (usage is not null)
        {
            await VaKoLinkConfigurationMetadata.SaveAsync(item, usage, VaKoLinkConfigurationMetadata.Scope.All);
        }
        else if (result.IsNullOrEmpty() && IsVaKoLinkWindows && VaKoLinkConfigurationMetadata.Supports(item))
        {
            VaKoLinkConfigurationMetadata.ReportFailure(item, VaKoLinkConfigurationMetadata.Scope.All);
        }
        return result;
    }

    private static async Task<string> DownloadAdditionalSubscriptions(SubItem item, string mainResult, bool blProxy, DownloadService downloadHandle)
    {
        var result = mainResult;

        // If main subscription result is Base64 encoded, decode it first
        if (result.IsNotEmpty() && Utils.IsBase64String(result))
        {
            result = Utils.Base64Decode(result);
        }

        // Process additional URL list
        var lstUrl = item.MoreUrl.TrimEx().Split(",") ?? [];
        foreach (var it in lstUrl)
        {
            var url2 = Utils.GetPunycode(it);
            if (url2.IsNullOrEmpty())
            {
                continue;
            }

            var additionalResult = await DownloadSubscriptionContent(downloadHandle, url2, blProxy, item.UserAgent);

            if (additionalResult.IsNotEmpty())
            {
                // Process additional subscription results, add to main result
                if (Utils.IsBase64String(additionalResult))
                {
                    result += Environment.NewLine + Utils.Base64Decode(additionalResult);
                }
                else
                {
                    result += Environment.NewLine + additionalResult;
                }
            }
        }

        return result;
    }

    private static async Task<bool> ProcessDownloadResult(Config config, string id, string result, string hashCode, Func<bool, string, Task> updateFunc)
    {
        if (result.IsNullOrEmpty())
        {
            await updateFunc?.Invoke(false, $"{hashCode}{ResUI.MsgSubscriptionDecodingFailed}");
            return false;
        }

        await updateFunc?.Invoke(false, $"{hashCode}{ResUI.MsgGetSubscriptionSuccessfully}");

        // If result is too short, display content directly
        if (!IsVaKoLinkWindows && result.Length < 99)
        {
            await updateFunc?.Invoke(false, $"{hashCode}{result}");
        }

        await updateFunc?.Invoke(false, $"{hashCode}{ResUI.MsgStartParsingSubscription}");

        // Add servers to configuration
        var ret = await ConfigHandler.AddBatchServers(config, result, id, true);
        if (ret <= 0)
        {
            Logging.SaveLog("FailedImportSubscription");
            if (!IsVaKoLinkWindows)
            {
                Logging.SaveLog(result);
            }
        }

        // Update completion message
        await updateFunc?.Invoke(false, ret > 0
                ? $"{hashCode}{ResUI.MsgUpdateSubscriptionEnd}"
                : $"{hashCode}{ResUI.MsgFailedImportSubscription}");

        return ret > 0;
    }
}
