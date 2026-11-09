using System.Net;
using System.Net.Http;
using System.Text.Json;

namespace VaKoLink.Updates;

internal sealed record ClientRelease(string Label, Version Version, string Sha256);

internal sealed class ClientUpdateFeed(HttpClient http, Uri releaseRoot)
{
    internal static readonly Uri GitHubReleaseRoot = new("https://github.com/Hell4ik/VaKoLink-Client/releases/");
    private const int ManifestLimit = 16 * 1024;

    internal async Task<ClientRelease?> CheckAsync(Version installed, CancellationToken token)
    {
        using var response = await GetAsync(new Uri(releaseRoot, "latest/download/vakolink-update.json"), token);
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
        using var response = await GetAsync(url, token);
        var length = response.Content.Headers.ContentLength;
        if (length is <= 0 or > UpdatePackage.MaxArchiveSize)
        {
            throw new InvalidDataException("Неверный размер пакета VaKoLink.");
        }

        await using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None,
            128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using var input = await response.Content.ReadAsStreamAsync(token);
        var buffer = new byte[128 * 1024];
        long total = 0;
        var displayedPercent = 0;
        int read;
        while ((read = await input.ReadAsync(buffer, token)) != 0)
        {
            total += read;
            if (total > UpdatePackage.MaxArchiveSize || total > length)
            {
                throw new InvalidDataException("Превышен допустимый размер пакета VaKoLink.");
            }
            await output.WriteAsync(buffer.AsMemory(0, read), token);
            if (length is > 0)
            {
                var percent = (int)Math.Min(99, total * 100 / length.Value);
                if (percent > displayedPercent)
                {
                    displayedPercent = percent;
                    progress.Report(percent);
                }
            }
        }

        output.Position = 0;
        if (length is { } declared && total != declared ||
            !await UpdatePackage.VerifyAsync(output, release.Sha256, token))
        {
            throw new InvalidDataException("SHA-256 пакета VaKoLink не совпадает с манифестом.");
        }
        progress.Report(100);
    }

    private async Task<HttpResponseMessage> GetAsync(Uri url, CancellationToken token)
    {
        for (var redirects = 0; redirects <= 6; redirects++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.UserAgent.ParseAdd("VaKoLink-Updater");
            var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token);
            if (response.IsSuccessStatusCode)
            {
                return response;
            }
            using (response)
            {
                if (response.StatusCode is HttpStatusCode.MovedPermanently or HttpStatusCode.Redirect or
                    HttpStatusCode.SeeOther or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect &&
                    response.Headers.Location is { } location)
                {
                    var target = location.IsAbsoluteUri ? location : new Uri(url, location);
                    if (!IsAllowedRedirect(target))
                    {
                        throw new HttpRequestException("Канал VaKoLink перенаправил запрос на неподдерживаемый адрес.");
                    }
                    url = target;
                    continue;
                }

                throw new HttpRequestException($"Канал VaKoLink недоступен (HTTP {(int)response.StatusCode}).",
                    null, response.StatusCode);
            }
        }
        throw new HttpRequestException("Слишком много перенаправлений канала VaKoLink.");
    }

    private bool IsAllowedRedirect(Uri target)
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
