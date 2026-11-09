using System.Net;
using System.Net.Http;
using System.Reflection;
using VaKoLink.Updates;

namespace v2rayN.Views;

public partial class MainWindow
{
    private static readonly string InstalledClientVersion = typeof(MainWindow).Assembly
        .GetCustomAttributes<AssemblyMetadataAttribute>()
        .Single(metadata => metadata.Key == "VaKoLinkVersion").Value!;

    private ClientRelease? _readyClientRelease;
    private string? _clientTransaction;
    private CancellationTokenSource? _clientUpdateCancellation;
    private bool _installingClient;

    private async Task<string> CheckClientUpdateAsync(VaKoLinkConnection connection)
    {
        var downloading = false;
        string? archive = null;
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(connection.ConnectedSessionToken);
        cancellation.CancelAfter(TimeSpan.FromSeconds(25));
        _clientUpdateCancellation = cancellation;
        try
        {
            if (_readyClientRelease is { } ready)
            {
                return $"v{ready.Label} проверена и готова к установке.";
            }
            if (!UpdatePackage.TryParseVersion(InstalledClientVersion, out var installed))
            {
                throw new InvalidDataException("Некорректная версия установленного клиента.");
            }
            using var http = CreateClientUpdateHttp(connection);
            var feed = new ClientUpdateFeed(http, ClientUpdateFeed.GitHubReleaseRoot);
            if (await feed.CheckAsync(installed, cancellation.Token) is not { } release)
            {
                return $"v{InstalledClientVersion} — актуально.";
            }

            downloading = true;
            cancellation.CancelAfter(TimeSpan.FromMinutes(15));
            var transaction = ClientUpdateProcess.CreateTransaction();
            archive = UpdatePackage.SafePath(transaction, UpdatePackage.ArchiveName);
            ShowUpdateCheckProgress($"VaKoLink v{release.Label} — скачивание");
            var progress = new Progress<int>(percent =>
            {
                if (_clientUpdateCancellation == cancellation)
                {
                    _clientUpdatePercent = Math.Max(_clientUpdatePercent, Math.Min(percent, 99));
                    ShowUpdateCheckProgress($"VaKoLink v{release.Label} — скачивание");
                }
            });
            await feed.DownloadAsync(release, archive, progress, cancellation.Token);
            _clientTransaction = transaction;
            _readyClientRelease = release;
            archive = null;
            return $"v{release.Label} проверена и готова к установке.";
        }
        catch (Exception ex)
        {
            Logging.SaveLog(downloading ? "Скачивание обновления VaKoLink" : "Проверка обновления VaKoLink", ex);
            if (ex is OperationCanceledException)
            {
                return downloading ? "скачивание прервано." : "проверка прервана.";
            }
            if (!downloading && ex is HttpRequestException { StatusCode: HttpStatusCode.NotFound })
            {
                return "манифест обновления недоступен (HTTP 404).";
            }
            return downloading ? $"не удалось подготовить пакет. {ex.Message}" : $"не удалось проверить версию. {ex.Message}";
        }
        finally
        {
            if (archive is not null)
            {
                DeleteClientUpdateArchive(archive);
            }
            _clientUpdateCancellation = null;
            _clientUpdatePercent = 100;
            ShowUpdateCheckProgress("Приложение проверено");
        }
    }

    private async void ClientUpdateAction_Click(object sender, RoutedEventArgs e)
    {
        if (_checkingUpdates || _updatingComponents || _installingClient ||
            _readyClientRelease is not { } release || _clientTransaction is not { } transaction ||
            AppManager.Instance.ConnectionModes is not { Ready: true, Busy: false } connection)
        {
            return;
        }

        _installingClient = true;
        var started = false;
        IsEnabled = false;
        ShowUpdateProgress(100, "Отключение VPN перед установкой");
        UpdateNodeControls();
        try
        {
            started = await connection.RunInstallationAsync(async resume =>
            {
                var results = await InstallPendingComponentsAsync();
                if (results.Count > 0)
                {
                    Logging.SaveLog(string.Join(Environment.NewLine, results));
                }
                ShowUpdateProgress(100, "Запуск установщика VaKoLink");
                ClientUpdateProcess.StartInstallation(transaction, release, resume);
            });
            if (started)
            {
                await AppManager.Instance.AppExitAsync(true);
            }
            else
            {
                MainSnackbar.MessageQueue?.Enqueue("Установка не началась. Проверьте статус VPN.");
            }
        }
        catch (Exception ex)
        {
            Logging.SaveLog("Запуск установки приложения VaKoLink", ex);
            MainSnackbar.MessageQueue?.Enqueue($"Не удалось запустить установку. {ex.Message}");
        }
        finally
        {
            if (!started)
            {
                _installingClient = false;
                IsEnabled = true;
                updateProgressPanel.Visibility = Visibility.Collapsed;
                UpdateNodeControls();
            }
        }
    }

    private void RenderClientUpdate(VaKoLinkConnection? connection)
    {
        clientUpdateAction.Visibility = _clientTransaction is null ? Visibility.Collapsed : Visibility.Visible;
        clientUpdateAction.IsEnabled = !_checkingUpdates && !_updatingComponents && !_installingClient &&
            connection is { Ready: true, Busy: false };
    }

    private void ShowPreviousClientUpdateResult()
    {
        try
        {
            if (ClientUpdateProcess.TakeResult() is { } result)
            {
                Logging.SaveLog(result);
                MainSnackbar.MessageQueue?.Enqueue(result);
            }
        }
        catch (IOException ex)
        {
            Logging.SaveLog("Чтение результата установки VaKoLink", ex);
        }
    }

    private void EndClientUpdate()
    {
        _clientUpdateCancellation?.Cancel();
        if (!_installingClient && _clientTransaction is { } transaction)
        {
            DeleteClientUpdateArchive(UpdatePackage.SafePath(transaction, UpdatePackage.ArchiveName));
        }
    }

    private static void DeleteClientUpdateArchive(string archive)
    {
        try
        {
            File.Delete(archive);
        }
        catch (IOException ex)
        {
            Logging.SaveLog("Очистка пакета VaKoLink", ex);
        }
    }

    private HttpClient CreateClientUpdateHttp(VaKoLinkConnection connection)
    {
        var updateViaProxy = _config.CheckUpdateItem.UpdateViaProxy;
        var proxy = updateViaProxy && connection.ConnectedProxyPort is { } port
            ? new WebProxy($"socks5://{Global.Loopback}:{port}")
            : null;
        return new HttpClient(new SocketsHttpHandler
        {
            UseProxy = updateViaProxy && (proxy is not null || !connection.IsConnected),
            Proxy = proxy,
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(12)
        });
    }
}
