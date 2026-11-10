using System.IO.Compression;

namespace ServiceLib.Services;

public partial class UpdateService
{
    private static readonly SemanticVersion VaKoLinkSingBoxMaxVersion = new(1, 14, int.MaxValue);

    private sealed record VaKoLinkRelease(string Tag, SemanticVersion Version, JsonElement Metadata = default);
    private sealed record VaKoLinkUpdateHttp(HttpClient Client, string Route);

    public sealed class VaKoLinkUpdateBatch : IDisposable
    {
        private readonly List<(string Preview, Func<Task<string>>? Install)> _items = [];
        internal string StagingPath { get; } = Utils.GetTempPath($"vakolink-update-{Utils.GetGuid()}");
        internal int Count => _items.Count;
        public bool HasChanges => _items.Any(item => item.Install is not null);
        public IReadOnlyList<string> Preview => _items.Select(item => item.Preview).ToArray();

        internal void Add(string preview, Func<Task<string>>? install = null) => _items.Add((preview, install));

        public async Task<IReadOnlyList<string>> InstallAsync()
        {
            var results = new List<string>();
            foreach (var (preview, install) in _items)
            {
                try
                {
                    results.Add(install is null ? preview : await install());
                }
                catch (Exception ex)
                {
                    Logging.SaveLog(preview, ex);
                    results.Add($"{preview}. Ошибка установки. {ex.Message}");
                }
            }
            return results;
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(StagingPath) && !Directory.EnumerateFiles(StagingPath, "*.backup", SearchOption.AllDirectories).Any())
                {
                    Directory.Delete(StagingPath, recursive: true);
                }
            }
            catch (IOException ex)
            {
                Logging.SaveLog(nameof(VaKoLinkUpdateBatch), ex);
            }
            catch (UnauthorizedAccessException ex)
            {
                Logging.SaveLog(nameof(VaKoLinkUpdateBatch), ex);
            }
        }
    }

    public async Task<VaKoLinkUpdateBatch> PrepareVaKoLinkUpdatesAsync(IWebProxy? proxy, bool useSystemProxy,
        IProgress<(int Percent, string Stage)>? progress = null, CancellationToken cancellationToken = default, bool viaTun = false)
    {
        using var client = CreateVaKoLinkUpdateClient(proxy, useSystemProxy);
        using var redirectClient = CreateVaKoLinkUpdateClient(proxy, useSystemProxy, followRedirects: false);
        var route = DescribeVaKoLinkUpdateRoute(proxy, useSystemProxy, viaTun);
        Logging.SaveLog($"Обновление VaKoLink | маршрут {route}");
        var http = new VaKoLinkUpdateHttp(client, route);
        var redirectHttp = new VaKoLinkUpdateHttp(redirectClient, route);
        var batch = new VaKoLinkUpdateBatch();
        (ECoreType Type, string Name)[] cores = [(ECoreType.Xray, "Xray"), (ECoreType.mihomo, "mihomo"), (ECoreType.sing_box, "sing-box")];
        void Report(double fraction, string stage)
        {
            progress?.Report(((int)((batch.Count + fraction) * 100 / (cores.Length + 1)), stage));
        }

        try
        {
            foreach (var (type, name) in cores)
            {
                var step = "проверка версии";
                void ReportCore(double fraction, string stage)
                {
                    step = stage;
                    Report(fraction, $"{name} — {stage}");
                }

                try
                {
                    ReportCore(0, step);
                    await PrepareVaKoLinkCoreAsync(http, redirectHttp, batch, type, name, ReportCore, cancellationToken);
                }
                catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
                {
                    Logging.SaveLog($"Обновление {name}", ex);
                    batch.Add($"{name} — ошибка ({step}). {ex.Message}");
                }
            }
            Report(0, "geoFiles — проверка файлов");
            await PrepareVaKoLinkGeoAsync(http, batch, Report, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            Report(0, "Проверка завершена");
            return batch;
        }
        catch
        {
            batch.Dispose();
            throw;
        }
    }

    public async Task<string> UpdateVaKoLinkGeoAsync()
    {
        var useSystemProxy = _config?.CheckUpdateItem.UpdateViaProxy == true;
        using var client = CreateVaKoLinkUpdateClient(null, useSystemProxy);
        using var batch = new VaKoLinkUpdateBatch();
        await PrepareVaKoLinkGeoAsync(new(client, DescribeVaKoLinkUpdateRoute(null, useSystemProxy, viaTun: false)), batch);
        return (await batch.InstallAsync()).Single();
    }

    private static string DescribeVaKoLinkUpdateRoute(IWebProxy? proxy, bool useSystemProxy, bool viaTun) =>
        proxy is WebProxy { Address: { } address } ? $"SOCKS5 {address.Host}:{address.Port}"
        : useSystemProxy ? "системный прокси (если настроен)"
        : viaTun ? "TUN (системный маршрут)"
        : "напрямую";

    private static HttpClient CreateVaKoLinkUpdateClient(IWebProxy? proxy, bool useSystemProxy, bool followRedirects = true)
    {
        var client = new HttpClient(new SocketsHttpHandler
        {
            UseProxy = proxy is not null || useSystemProxy,
            Proxy = proxy,
            AllowAutoRedirect = followRedirects,
            ConnectTimeout = TimeSpan.FromSeconds(12)
        }) { Timeout = Timeout.InfiniteTimeSpan };
        client.DefaultRequestHeaders.UserAgent.ParseAdd($"VaKoLink/{Utils.GetVersionInfo()}");
        return client;
    }

    private async Task PrepareVaKoLinkCoreAsync(VaKoLinkUpdateHttp http, VaKoLinkUpdateHttp redirectHttp,
        VaKoLinkUpdateBatch batch, ECoreType type, string name,
        Action<double, string> report, CancellationToken cancellationToken)
    {
        var core = CoreInfoManager.Instance.GetCoreInfo(type) ?? throw new InvalidOperationException("Неизвестное ядро.");
        var release = await GetVaKoLinkLatestReleaseAsync(http, redirectHttp, core, name, cancellationToken);
        var maxVersion = core.LockedMaxVersion ?? (type == ECoreType.sing_box ? VaKoLinkSingBoxMaxVersion : null);
        if (maxVersion is not null && release.Version > maxVersion)
        {
            report(0, "поиск совместимой версии");
            var branch = type == ECoreType.sing_box && maxVersion.Equals(VaKoLinkSingBoxMaxVersion)
                ? "1.14.x" : $"до {maxVersion.ToStandardVersionString("v")}";
            try
            {
                var compatible = await FindVaKoLinkCompatibleReleaseAsync(http, core, name, maxVersion, cancellationToken);
                if (compatible is null)
                {
                    batch.Add($"{name} — не удалось подтвердить совместимый стабильный релиз ({branch}).");
                    return;
                }
                release = compatible;
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
            {
                batch.Add($"{name} — не удалось подтвердить совместимый стабильный релиз ({branch}). {ex.Message}");
                return;
            }
        }

        var existing = CoreInfoManager.Instance.GetCoreExecFile(core, out _);
        var installed = string.IsNullOrEmpty(existing) ? null : await GetCoreVersion(type, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        var previous = installed?.ToStandardVersionString("v");
        if (installed is not null && maxVersion is not null && installed > maxVersion)
        {
            batch.Add($"{name} — установленная версия {previous} вне поддерживаемой ветки. Совместимый релиз {release.Tag}.");
            return;
        }
        if (installed is not null && installed >= release.Version)
        {
            batch.Add($"{name} — Актуально ({previous})");
            return;
        }

        var tag = release.Tag;
        var url = string.Format(core.DownloadUrlWin64, tag, tag.RemovePrefix("v"));
        var assetName = Path.GetFileName(new Uri(url).AbsolutePath);
        string Unconfirmed(string reason) => $"{name} — Новая версия найдена, пакет не подтверждён ({tag}). {reason}";

        report(0, "метаданные пакета и SHA-256");
        string checksum;
        long? assetId;
        try
        {
            (checksum, assetId) = await GetVaKoLinkAssetAsync(http, core, release, name, assetName, url, cancellationToken);
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            batch.Add(Unconfirmed(ex.Message));
            return;
        }

        var installDir = Directory.CreateDirectory(Path.Combine(batch.StagingPath, type.ToString())).FullName;
        var archivePath = Path.Combine(installDir, assetName);
        try
        {
            report(0, "скачивание");
            try
            {
                await DownloadVaKoLinkFileAsync(http, url, archivePath, fraction => report(fraction * 0.9, "скачивание"),
                    cancellationToken, $"{name}: скачивание ZIP");
            }
            catch (HttpRequestException ex) when (IsRetryable(ex.StatusCode) && assetId is { } id)
            {
                var assetUrl = $"{core.ReleaseApiUrl}/assets/{id}";
                report(0, "скачивание через GitHub API");
                await DownloadVaKoLinkFileAsync(http, assetUrl, archivePath,
                    fraction => report(fraction * 0.9, "скачивание через GitHub API"), cancellationToken,
                    $"{name}: скачивание ZIP через API", binaryAsset: true);
            }
            report(0.9, "проверка SHA-256");
            await using var verifiedArchive = await OpenVerifiedVaKoLinkArchiveAsync(archivePath, checksum, assetName, cancellationToken);
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            if (ex is not HttpRequestException)
            {
                LogVaKoLinkUpdateFailure(http, $"{name}: подготовка ZIP", new Uri(url).Host, null, ex);
            }
            batch.Add(Unconfirmed(ex.Message));
            return;
        }

        var downloaded = previous is null or "v0.0.0"
            ? $"скачано · {tag}"
            : $"скачано · {previous} → {tag}";
        batch.Add($"{name} — {downloaded}", async () =>
        {
            Stream stream;
            try
            {
                stream = await OpenVerifiedVaKoLinkArchiveAsync(archivePath, checksum, assetName, CancellationToken.None);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
            {
                LogVaKoLinkUpdateFailure(http, $"{name}: проверка SHA-256 перед установкой", new Uri(url).Host, null, ex);
                return Unconfirmed(ex.Message);
            }
            await using var verifiedArchive = stream;
            using var archive = new ZipArchive(verifiedArchive, ZipArchiveMode.Read, leaveOpen: true);
            var executable = $"{core.CoreExes.Last()}.exe";
            var entry = archive.Entries.SingleOrDefault(item => item.Name == executable ||
                (type == ECoreType.mihomo && (item.Name == Path.ChangeExtension(assetName, ".exe") ||
                    core.CoreExes.Any(name => item.Name == name + ".exe"))));
            if (entry is null || entry.Length == 0)
            {
                throw new InvalidDataException($"В пакете {assetName} отсутствует {executable}.");
            }

            var files = new List<string>();
            foreach (var dependency in type switch
            {
                ECoreType.Xray => new[] { "wintun.dll" },
                ECoreType.sing_box => new[] { "libcronet.dll", "wintun.dll" },
                _ => Array.Empty<string>()
            })
            {
                var library = archive.Entries.SingleOrDefault(item => item.Name == dependency);
                if (library is not null)
                {
                    library.ExtractToFile(Path.Combine(installDir, dependency));
                    files.Add(dependency);
                }
            }

            var executableName = string.IsNullOrEmpty(existing) ? executable : Path.GetFileName(existing);
            entry.ExtractToFile(Path.Combine(installDir, executableName));
            files.Add(executableName);
            InstallVaKoLinkFiles(files, installDir, Utils.GetBinPath("", type.ToString()));
            var result = previous switch
            {
                null => $"установлено {tag}",
                "v0.0.0" => $"обновлено до {tag} (прежняя версия не определена)",
                _ => $"{previous} → {tag}"
            };
            return $"{name} — {result}";
        });
    }

    private static async Task<VaKoLinkRelease> GetVaKoLinkLatestReleaseAsync(VaKoLinkUpdateHttp http,
        VaKoLinkUpdateHttp redirectHttp, CoreInfo core, string name, CancellationToken cancellationToken)
    {
        var latest = new Uri($"{core.Url}/latest");
        var tagPrefix = new Uri(core.Url).AbsolutePath.TrimEnd('/') + "/tag/";
        try
        {
            return await ReadVaKoLinkResourceAsync(redirectHttp, latest.AbsoluteUri, $"{name}: тег из редиректа", (response, _) =>
            {
                var location = response.Headers.Location;
                if (location is not null && !location.IsAbsoluteUri)
                {
                    location = new Uri(latest, location);
                }
                if ((int)response.StatusCode is >= 300 and < 400 && location is not null &&
                    location.Scheme == Uri.UriSchemeHttps && location.Host == latest.Host &&
                    location.AbsolutePath.StartsWith(tagPrefix, StringComparison.OrdinalIgnoreCase) &&
                    ParseVaKoLinkStableTag(Uri.UnescapeDataString(location.AbsolutePath[tagPrefix.Length..])) is { } release)
                {
                    return Task.FromResult(release);
                }
                throw new InvalidDataException("GitHub не вернул тег стабильного релиза в редиректе.");
            }, cancellationToken, acceptRedirect: true);
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested && ex is HttpRequestException or InvalidDataException)
        {
            return await ReadVaKoLinkResourceAsync(http, $"{core.ReleaseApiUrl}/latest", $"{name}: версия через API",
                async (response, token) =>
                {
                    using var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(token), cancellationToken: token);
                    return ParseVaKoLinkRelease(document.RootElement)
                        ?? throw new InvalidDataException("GitHub API не подтвердил стабильную версию.");
                }, cancellationToken);
        }
    }

    private static async Task<VaKoLinkRelease?> FindVaKoLinkCompatibleReleaseAsync(VaKoLinkUpdateHttp http, CoreInfo core,
        string name, SemanticVersion maxVersion, CancellationToken cancellationToken)
    {
        const int pageSize = 50;
        for (var page = 1; page <= 5; page++)
        {
            var (match, count) = await ReadVaKoLinkResourceAsync(http, $"{core.ReleaseApiUrl}?per_page={pageSize}&page={page}",
                $"{name}: поиск совместимой версии", async (response, token) =>
                {
                    using var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(token), cancellationToken: token);
                    var releases = document.RootElement;
                    var candidate = releases.EnumerateArray()
                        .Select(ParseVaKoLinkRelease)
                        .Where(release => release is not null && release.Version <= maxVersion)
                        .MaxBy(release => release!.Version);
                    return (candidate, releases.GetArrayLength());
                }, cancellationToken);
            if (match is not null || count < pageSize)
            {
                return match;
            }
        }
        return null;
    }

    private static VaKoLinkRelease? ParseVaKoLinkRelease(JsonElement release)
    {
        if (release.ValueKind != JsonValueKind.Object || !release.TryGetProperty("draft", out var draft) ||
            draft.ValueKind != JsonValueKind.False || !release.TryGetProperty("prerelease", out var prerelease) ||
            prerelease.ValueKind != JsonValueKind.False || !release.TryGetProperty("tag_name", out var tag) ||
            tag.ValueKind != JsonValueKind.String)
        {
            return null;
        }
        return ParseVaKoLinkStableTag(tag.GetString()) is { } stable ? stable with { Metadata = release.Clone() } : null;
    }

    private static VaKoLinkRelease? ParseVaKoLinkStableTag(string? tag)
    {
        if (tag is null || !Regex.IsMatch(tag, @"\Av?[0-9]+\.[0-9]+\.[0-9]+\z"))
        {
            return null;
        }
        var version = new SemanticVersion(tag);
        return version.Equals(new SemanticVersion(0, 0, 0)) ? null : new(tag, version);
    }

    private static async Task<(string Checksum, long? AssetId)> GetVaKoLinkAssetAsync(VaKoLinkUpdateHttp http, CoreInfo core,
        VaKoLinkRelease release, string name, string assetName, string downloadUrl, CancellationToken cancellationToken)
    {
        var url = $"{core.ReleaseApiUrl}/tags/{Uri.EscapeDataString(release.Tag)}";
        var stage = $"{name}: метаданные пакета и SHA-256";
        (string Checksum, long? AssetId) ReadAsset(JsonElement metadata)
        {
            if (metadata.TryGetProperty("assets", out var assets) && assets.ValueKind == JsonValueKind.Array)
            {
                foreach (var asset in assets.EnumerateArray())
                {
                    if (asset.GetProperty("name").GetString() == assetName &&
                        asset.GetProperty("browser_download_url").GetString() == downloadUrl &&
                        asset.TryGetProperty("digest", out var digest) && digest.ValueKind == JsonValueKind.String &&
                        digest.GetString() is { Length: 71 } checksum && checksum.StartsWith("sha256:", StringComparison.Ordinal) &&
                        checksum[7..].All(Uri.IsHexDigit))
                    {
                        long? id = asset.TryGetProperty("id", out var idValue) && idValue.TryGetInt64(out var parsedId) && parsedId > 0
                            ? parsedId : null;
                        return (checksum[7..], id);
                    }
                }
            }
            throw new InvalidDataException($"В релизе {release.Tag} нет пакета {assetName} с SHA-256.");
        }

        if (release.Metadata.ValueKind == JsonValueKind.Object)
        {
            try
            {
                return ReadAsset(release.Metadata);
            }
            catch (Exception ex)
            {
                LogVaKoLinkUpdateFailure(http, stage, new Uri(url).Host, HttpStatusCode.OK, ex);
                throw;
            }
        }

        return await ReadVaKoLinkResourceAsync(http, url, stage, async (response, token) =>
        {
            using var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(token), cancellationToken: token);
            if (ParseVaKoLinkRelease(document.RootElement)?.Tag != release.Tag)
            {
                throw new InvalidDataException("Метаданные не подтвердили выбранный стабильный релиз.");
            }
            return ReadAsset(document.RootElement);
        }, cancellationToken);
    }

    private static async Task VerifyVaKoLinkChecksumAsync(Stream stream, string checksum, string fileName, CancellationToken token)
    {
        var hash = await SHA256.HashDataAsync(stream, token);
        if (!Convert.ToHexString(hash).Equals(checksum, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException($"Контрольная сумма {fileName} не совпала.");
        }
    }

    private static async Task<Stream> OpenVerifiedVaKoLinkArchiveAsync(string path, string checksum, string fileName, CancellationToken token)
    {
        var stream = File.OpenRead(path);
        try
        {
            await VerifyVaKoLinkChecksumAsync(stream, checksum, fileName, token);
            stream.Position = 0;
            return stream;
        }
        catch
        {
            await stream.DisposeAsync();
            throw;
        }
    }

    private static void InstallVaKoLinkFiles(List<string> files, string source, string target)
    {
        var installed = new List<(string Destination, string? Backup)>();
        try
        {
            foreach (var name in files)
            {
                var staged = Path.Combine(source, name);
                var destination = Path.Combine(target, name);
                if (File.Exists(destination))
                {
                    var backup = staged + ".backup";
                    File.Replace(staged, destination, backup);
                    installed.Add((destination, backup));
                }
                else
                {
                    File.Move(staged, destination);
                    installed.Add((destination, null));
                }
            }
        }
        catch
        {
            foreach (var (destination, backup) in installed.AsEnumerable().Reverse())
            {
                if (backup is null)
                {
                    File.Delete(destination);
                }
                else
                {
                    File.Move(backup, destination, overwrite: true);
                }
            }
            throw;
        }

        foreach (var (_, backup) in installed)
        {
            if (backup is not null)
            {
                File.Delete(backup);
            }
        }
    }

    private async Task PrepareVaKoLinkGeoAsync(VaKoLinkUpdateHttp http, VaKoLinkUpdateBatch batch,
        Action<double, string>? report = null, CancellationToken cancellationToken = default)
    {
        try
        {
            var requests = GetGeoFilesRequest().Concat(GetOtherFilesRequest()).Concat(await GetSrsFileAllRequest()).ToList();
            var errors = new List<string>();
            var current = 0;
            var prepared = new List<(string FileName, string Staged, string Target)>();
            var completed = 0;
            foreach (var request in requests)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var fileName = request.DisplayFileName;
                void ReportFile(double fraction)
                {
                    report?.Invoke((completed + fraction) / requests.Count, $"geoFiles — файл {completed + 1} из {requests.Count}");
                }
                ReportFile(0);
                if (string.IsNullOrEmpty(fileName) || fileName != Path.GetFileName(fileName) ||
                    fileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
                {
                    errors.Add("недопустимое имя geoFile");
                    completed++;
                    continue;
                }

                Directory.CreateDirectory(batch.StagingPath);
                var staged = Path.Combine(batch.StagingPath, $"{Utils.GetGuid()}.download");
                try
                {
                    await DownloadVaKoLinkGeoFileAsync(http, request, staged, fraction => ReportFile(fraction * 0.9), cancellationToken);
                    if (await HasSameGeoContentAsync(staged, request.FilePath, cancellationToken))
                    {
                        current++;
                        File.Delete(staged);
                    }
                    else
                    {
                        prepared.Add((fileName, staged, request.FilePath));
                    }
                }
                catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
                {
                    Logging.SaveLog($"Обновление {fileName}", ex);
                    errors.Add($"{fileName} ({ex.Message})");
                }
                finally
                {
                    completed++;
                }
            }
            string Summary(string label, int count)
            {
                if (errors.Count == 0 && count == 0)
                {
                    return $"geoFiles — актуальны ({current} файлов)";
                }
                var summary = $"geoFiles — {label}: {count}, актуально: {current}";
                return errors.Count == 0 ? summary : $"{summary}. Ошибки: {string.Join(", ", errors)}";
            }

            batch.Add(Summary("скачано", prepared.Count), prepared.Count == 0 ? null : () =>
            {
                var installed = 0;
                foreach (var (fileName, staged, target) in prepared)
                {
                    try
                    {
                        File.Move(staged, target, overwrite: true);
                        installed++;
                    }
                    catch (Exception ex)
                    {
                        Logging.SaveLog($"Установка {fileName}", ex);
                        errors.Add($"{fileName} ({ex.Message})");
                    }
                }
                return Task.FromResult(Summary("обновлено", installed));
            });
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            Logging.SaveLog("Обновление geoFiles", ex);
            batch.Add($"geoFiles — ошибка. {ex.Message}");
        }
    }

    private static async Task DownloadVaKoLinkGeoFileAsync(VaKoLinkUpdateHttp http, FileDownloadRequest request,
        string staged, Action<double> report, CancellationToken cancellationToken)
    {
        var fileName = request.DisplayFileName;
        try
        {
            await DownloadVaKoLinkFileAsync(http, request.FileUrl, staged, report, cancellationToken, $"{fileName}: скачивание");
        }
        catch (HttpRequestException ex) when (IsRetryable(ex.StatusCode) && GetVaKoLinkGeoMirror(request) is { } mirror)
        {
            Logging.SaveLog($"Переход на резервный источник {fileName}", ex);
            var checksumText = await ReadVaKoLinkResourceAsync(http, mirror + ".sha256sum", $"{fileName}: SHA-256 резерва",
                (response, token) => response.Content.ReadAsStringAsync(token), cancellationToken);
            var checksum = checksumText.Trim().Split(' ', '\t')[0];
            if (checksum.Length != 64 || !checksum.All(Uri.IsHexDigit))
            {
                throw new InvalidDataException($"Резервный источник не предоставил SHA-256 для {fileName}.");
            }

            await DownloadVaKoLinkFileAsync(http, mirror, staged, report, cancellationToken, $"{fileName}: резервное скачивание");
            await using var downloaded = File.OpenRead(staged);
            await VerifyVaKoLinkChecksumAsync(downloaded, checksum, request.FileName, cancellationToken);
        }
    }

    private static string? GetVaKoLinkGeoMirror(FileDownloadRequest request) => (request.FileName, request.FileUrl) switch
    {
        ("geoip.dat" or "geosite.dat", var url) when url == string.Format(Global.GeoUrl, Path.GetFileNameWithoutExtension(request.FileName))
            => $"https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/{request.FileName}",
        ("geoip.metadb", "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb")
            => "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb",
        _ => null
    };

    private static async Task<bool> HasSameGeoContentAsync(string staged, string target, CancellationToken cancellationToken)
    {
        if (!File.Exists(target) || new FileInfo(staged).Length != new FileInfo(target).Length)
        {
            return false;
        }
        await using var downloaded = File.OpenRead(staged);
        await using var existing = File.OpenRead(target);
        var downloadedHash = await SHA256.HashDataAsync(downloaded, cancellationToken);
        var existingHash = await SHA256.HashDataAsync(existing, cancellationToken);
        return downloadedHash.AsSpan().SequenceEqual(existingHash);
    }

    private static Task DownloadVaKoLinkFileAsync(VaKoLinkUpdateHttp http, string url, string fileName, Action<double> report,
        CancellationToken cancellationToken, string stage, bool binaryAsset = false) =>
        ReadVaKoLinkResourceAsync(http, url, stage, async (response, token) =>
        {
            if (binaryAsset && response.Content.Headers.ContentType?.MediaType is "application/json" or "application/vnd.github+json")
            {
                throw new InvalidDataException("GitHub API вернул описание файла вместо архива.");
            }
            await using var file = new FileStream(fileName, FileMode.Create, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.Asynchronous);
            await using var content = await response.Content.ReadAsStreamAsync(token);
            var expectedLength = response.Content.Headers.ContentLength;
            var buffer = new byte[64 * 1024];
            long received = 0;
            var reportedPercent = 0;
            int read;
            while ((read = await content.ReadAsync(buffer, token)) != 0)
            {
                await file.WriteAsync(buffer.AsMemory(0, read), token);
                received += read;
                if (expectedLength is > 0)
                {
                    var percent = (int)Math.Min(100, received * 100d / expectedLength.Value);
                    if (percent > reportedPercent)
                    {
                        reportedPercent = percent;
                        report(percent / 100d);
                    }
                }
            }
            if (received == 0 || expectedLength is { } length && length != received)
            {
                throw new HttpRequestException("Файл скачан не полностью.");
            }
            return true;
        }, cancellationToken, binaryAsset);

    private static bool IsRetryable(HttpStatusCode? status) =>
        status is null or HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests or
            HttpStatusCode.BadGateway or HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout;

    private static void LogVaKoLinkUpdateFailure(VaKoLinkUpdateHttp http, string stage, string domain, HttpStatusCode? status, Exception ex)
    {
        var code = status is { } value ? ((int)value).ToString() : "нет статуса";
        Logging.SaveLog($"Обновление VaKoLink | этап {stage} | домен {domain} | HTTP {code} | маршрут {http.Route}", ex);
    }

    private static async Task<T> ReadVaKoLinkResourceAsync<T>(VaKoLinkUpdateHttp http, string url, string stage,
        Func<HttpResponseMessage, CancellationToken, Task<T>> read, CancellationToken cancellationToken,
        bool binaryAsset = false, bool acceptRedirect = false)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new InvalidDataException("Источник обновления должен использовать HTTPS.");
        }

        for (var attempt = 0; ; attempt++)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(acceptRedirect ? TimeSpan.FromSeconds(15) : TimeSpan.FromMinutes(2));
            var domain = uri.Host;
            HttpStatusCode? responseStatus = null;
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                if (binaryAsset)
                {
                    request.Headers.Accept.ParseAdd("application/octet-stream");
                }
                using var response = await http.Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
                domain = response.RequestMessage?.RequestUri?.Host ?? domain;
                responseStatus = response.StatusCode;
                if (!acceptRedirect || (int)response.StatusCode is < 300 or >= 400)
                {
                    response.EnsureSuccessStatusCode();
                }
                return await read(response, timeout.Token);
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
            {
                var status = (ex as HttpRequestException)?.StatusCode;
                LogVaKoLinkUpdateFailure(http, stage, domain, responseStatus ?? status, ex);
                if (ex is not (HttpRequestException or HttpIOException or OperationCanceledException))
                {
                    throw;
                }
                if (!acceptRedirect && attempt == 0 && IsRetryable(status))
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(750), cancellationToken);
                    continue;
                }
                var detail = status switch
                {
                    HttpStatusCode.GatewayTimeout => "HTTP 504 — шлюз не дождался ответа",
                    { } code => $"HTTP {(int)code}",
                    _ when ex is OperationCanceledException => "истекло время ожидания",
                    _ => "не удалось получить ответ"
                };
                throw new HttpRequestException($"{domain} — {detail}.", ex, status);
            }
        }
    }
}
