using System.Net;
using System.Net.Http;
using System.Text.Json;
using ServiceLib.Helper;
using ServiceLib.Models.Dto;

namespace VaKoLink.Updates;

internal sealed record ClientRelease(string Label, Version Version, string Sha256);

internal sealed class ClientUpdateFeed(Func<HttpMessageHandler> createTransport, Uri releaseRoot)
{
    internal static readonly Uri GitHubReleaseRoot = new("https://github.com/Hell4ik/VaKoLink-Client/releases/");
    private const int ManifestLimit = 16 * 1024;

    internal async Task<ClientRelease?> CheckAsync(Version installed, CancellationToken token)
    {
        using var http = new HttpClient(new ReleaseHandler(createTransport(), releaseRoot, archive: false));
        using var response = await http.GetAsync(new Uri(releaseRoot, "latest/download/vakolink-update.json"),
            HttpCompletionOption.ResponseHeadersRead, token);
        if (response.Content.Headers.ContentLength > ManifestLimit)
        {
            throw new InvalidDataException("Манифест VaKoLink слишком большой.");
        }
        await using var input = await response.Content.ReadAsStreamAsync(token);
        var bytes = new byte[ManifestLimit + 1];
        var count = await input.ReadAtLeastAsync(bytes, bytes.Length, false, token);
        if (count > ManifestLimit)
        {
            throw new InvalidDataException("Манифест VaKoLink слишком большой.");
        }
        using var json = JsonDocument.Parse(bytes.AsMemory(0, count), new JsonDocumentOptions { MaxDepth = 8 });
        var root = json.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("version", out var labelElement) || labelElement.ValueKind != JsonValueKind.String ||
            labelElement.GetString() is not { } label || !UpdatePackage.TryParseVersion(label, out var version) ||
            !root.TryGetProperty("sha256", out var shaElement) || shaElement.ValueKind != JsonValueKind.String ||
            shaElement.GetString() is not { } sha256 || !UpdatePackage.IsSha256(sha256))
        {
            throw new InvalidDataException("В манифесте VaKoLink указана неверная версия или SHA-256.");
        }
        return version > installed ? new ClientRelease(label, version, sha256) : null;
    }

    internal async Task DownloadAsync(ClientRelease release, string destination, IProgress<int> progress,
        CancellationToken token)
    {
        var url = new Uri(releaseRoot, $"download/v{release.Label}/{UpdatePackage.AssetName(release.Label)}");
        var request = new FileDownloadRequest { FileUrl = url.AbsoluteUri, FilePath = destination };
        FileDownloadState? result = null;
        var displayedPercent = 0;
        await DownloaderHelper.Instance.DownloadFileAsync(null, request, state =>
        {
            if (state.Completed)
            {
                result = state;
            }
            else if (state.TotalBytes > 0)
            {
                var percent = (int)Math.Min(99, state.DownloadedBytes * 100 / state.TotalBytes);
                if (percent > displayedPercent)
                {
                    displayedPercent = percent;
                    progress.Report(percent);
                }
            }
        }, token, () => new ReleaseHandler(createTransport(), releaseRoot, archive: true));

        token.ThrowIfCancellationRequested();
        if (result is null || result.Error is not null || !File.Exists(destination))
        {
            throw new IOException(result?.Error?.Message ?? "Загрузка пакета VaKoLink не завершилась.", result?.Error);
        }

        await using var output = File.OpenRead(destination);
        if (!await UpdatePackage.VerifyAsync(output, release.Sha256, token))
        {
            throw new InvalidDataException("SHA-256 пакета VaKoLink не совпадает с манифестом.");
        }
        progress.Report(100);
    }

    private sealed class ReleaseHandler(HttpMessageHandler transport, Uri releaseRoot, bool archive) : DelegatingHandler(transport)
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            var url = request.RequestUri!;
            for (var redirects = 0; redirects <= 6; redirects++)
            {
                if (!IsAllowed(url))
                {
                    throw new HttpRequestException("Канал VaKoLink перенаправил запрос на неподдерживаемый адрес.");
                }
                using var next = new HttpRequestMessage(request.Method, url);
                foreach (var header in request.Headers)
                {
                    next.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
                if (next.Headers.UserAgent.Count == 0)
                {
                    next.Headers.UserAgent.ParseAdd("VaKoLink-Updater");
                }
                var response = await base.SendAsync(next, token).ConfigureAwait(false);
                if (response.StatusCode is HttpStatusCode.MovedPermanently or HttpStatusCode.Redirect or
                    HttpStatusCode.SeeOther or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect &&
                    response.Headers.Location is { } location)
                {
                    response.Dispose();
                    url = location.IsAbsoluteUri ? location : new Uri(url, location);
                    continue;
                }
                if (response.IsSuccessStatusCode)
                {
                    var length = response.StatusCode == HttpStatusCode.PartialContent
                        ? response.Content.Headers.ContentRange?.Length
                        : response.Content.Headers.ContentLength;
                    if (archive && (length is null or <= 0 or > UpdatePackage.MaxArchiveSize ||
                        response.Content.Headers.ContentLength > length))
                    {
                        response.Dispose();
                        throw new InvalidDataException("Неверный размер пакета VaKoLink.");
                    }
                    return response;
                }
                response.Dispose();
                throw new HttpRequestException($"Канал VaKoLink недоступен (HTTP {(int)response.StatusCode}).", null, response.StatusCode);
            }
            throw new HttpRequestException("Слишком много перенаправлений канала VaKoLink.");
        }

        private bool IsAllowed(Uri target)
        {
            if (target.UserInfo.Length != 0 || target.Scheme != releaseRoot.Scheme)
            {
                return false;
            }
            if (target.Host == releaseRoot.Host && target.Port == releaseRoot.Port)
            {
                return target.AbsolutePath.StartsWith(releaseRoot.AbsolutePath, StringComparison.Ordinal);
            }
            return releaseRoot == GitHubReleaseRoot && target.IsDefaultPort &&
                target.Host is "release-assets.githubusercontent.com" or "objects.githubusercontent.com" or
                    "github-releases.githubusercontent.com";
        }
    }
}
