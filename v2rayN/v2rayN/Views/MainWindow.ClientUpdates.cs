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

    private ClientRelease? _offeredClientRelease;
    private string? _clientTransaction;
    private string? _clientUpdateMessage;
    private CancellationTokenSource? _clientUpdateCancellation;
    private bool _clientUpdateBusy;
    private bool _installingClient;

    private async Task CheckClientUpdateAsync(VaKoLinkConnection connection)
    {
        if (_clientTransaction is not null)
        {
            return;
        }
        _offeredClientRelease = null;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        _clientUpdateCancellation = timeout;
        _clientUpdateBusy = true;
        _clientUpdateMessage = "Проверяем версию…";
        UpdateNodeControls();
        try
        {
            if (!UpdatePackage.TryParseVersion(InstalledClientVersion, out var installed))
            {
                throw new InvalidDataException("Некорректная версия установленного клиента.");
            }
            using var http = CreateClientUpdateHttp(connection);
            var feed = new ClientUpdateFeed(http, ClientUpdateFeed.GitHubReleaseRoot);
            _offeredClientRelease = await feed.CheckAsync(installed, timeout.Token);
            _clientUpdateMessage = _offeredClientRelease is { } release
                ? $"Доступна v{release.Label}. Установлена v{InstalledClientVersion}."
                : $"v{InstalledClientVersion} — актуально.";
        }
        catch (Exception ex)
        {
            Logging.SaveLog("Проверка обновления приложения VaKoLink", ex);
            _clientUpdateMessage = ex is HttpRequestException { StatusCode: HttpStatusCode.NotFound }
                ? "Манифест обновления недоступен (HTTP 404). Проверьте публикацию релиза и доступ к каналу."
                : ex is OperationCanceledException
                    ? "Истекло время проверки обновления."
                    : $"Не удалось проверить обновление. {ex.Message}";
        }
        finally
        {
            _clientUpdateCancellation = null;
            _clientUpdateBusy = false;
            UpdateNodeControls();
        }
    }

    private async void ClientUpdateAction_Click(object sender, RoutedEventArgs e)
    {
        if (_clientUpdateBusy || _installingClient || _offeredClientRelease is not { } release ||
            AppManager.Instance.ConnectionModes is not { } connection)
        {
            return;
        }

        if (_clientTransaction is { } transaction)
        {
            await InstallClientUpdateAsync(connection, release, transaction);
        }
        else
        {
            await DownloadClientUpdateAsync(connection, release);
        }
    }

    private async Task DownloadClientUpdateAsync(VaKoLinkConnection connection, ClientRelease release)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(15));
        _clientUpdateCancellation = timeout;
        _clientUpdateBusy = true;
        _clientUpdateMessage = $"Скачиваем v{release.Label}…";
        UpdateNodeControls();
        string? archive = null;
        try
        {
            var transaction = ClientUpdateProcess.CreateTransaction();
            archive = UpdatePackage.SafePath(transaction, UpdatePackage.ArchiveName);
            using var http = CreateClientUpdateHttp(connection);
            var feed = new ClientUpdateFeed(http, ClientUpdateFeed.GitHubReleaseRoot);
            var progress = new Progress<int>(percent =>
            {
                if (_clientUpdateCancellation == timeout)
                {
                    _clientUpdateMessage = $"Скачиваем v{release.Label} · {percent}%";
                    RenderClientUpdate(connection);
                }
            });
            await feed.DownloadAsync(release, archive, progress, timeout.Token);
            _clientTransaction = transaction;
            archive = null;
            _clientUpdateMessage = $"Пакет v{release.Label} проверен.";
        }
        catch (Exception ex)
        {
            Logging.SaveLog("Скачивание обновления приложения VaKoLink", ex);
            _clientUpdateMessage = ex is OperationCanceledException
                ? "Скачивание обновления прервано."
                : $"Не удалось скачать обновление. {ex.Message}";
        }
        finally
        {
            if (archive is not null)
            {
                DeleteClientUpdateArchive(archive);
            }
            _clientUpdateCancellation = null;
            _clientUpdateBusy = false;
            UpdateNodeControls();
        }
    }

    private async Task InstallClientUpdateAsync(VaKoLinkConnection connection, ClientRelease release, string transaction)
    {
        if (connection.NeedsDisconnect || _updatingComponents || _preparedUpdate is not null)
        {
            return;
        }
        _clientUpdateBusy = true;
        UpdateNodeControls();
        try
        {
            if (!await connection.RunWhileDisconnectedAsync(() =>
                {
                    ClientUpdateProcess.StartInstallation(transaction, release);
                    _installingClient = true;
                    IsEnabled = false;
                    return Task.CompletedTask;
                }))
            {
                return;
            }
            await AppManager.Instance.AppExitAsync(true);
        }
        catch (Exception ex)
        {
            Logging.SaveLog("Запуск установки приложения VaKoLink", ex);
            _clientUpdateMessage = $"Не удалось запустить установку. {ex.Message}";
        }
        finally
        {
            _clientUpdateBusy = false;
            UpdateNodeControls();
        }
    }

    private void RenderClientUpdate(VaKoLinkConnection? connection)
    {
        clientUpdatePanel.Visibility = _clientUpdateMessage is null ? Visibility.Collapsed : Visibility.Visible;
        clientUpdateStatus.Text = "Приложение VaKoLink — " + _clientUpdateMessage +
            (_clientTransaction is not null && connection?.NeedsDisconnect == true ? " Отключите VPN для установки." : "");
        clientUpdateAction.Visibility = _offeredClientRelease is null ? Visibility.Collapsed : Visibility.Visible;
        clientUpdateAction.Content = _clientTransaction is null ? "Скачать обновление" : "Установить";
        clientUpdateAction.IsEnabled = !_clientUpdateBusy && !_installingClient &&
            (_clientTransaction is null || connection is { Ready: true, Busy: false, NeedsDisconnect: false } &&
                !_updatingComponents && _preparedUpdate is null);
    }

    private void ShowPreviousClientUpdateResult()
    {
        try
        {
            if (ClientUpdateProcess.TakeResult() is { } result)
            {
                _clientUpdateMessage = result;
                UpdateNodeControls();
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
