using System.IO;
using System.Reflection;
using System.Text.Json;

namespace v2rayN.Manager;

internal sealed record TransportStep(string Stage, long FirstMilliseconds, long LastMilliseconds, int Count);
internal sealed record TransportNetworkChange(string Phase, string Category, int? Interface, string? AddressFamily,
    string Field, string Change);
internal sealed record TransportProbeResult(bool Socks5, bool Tcp, bool Udp, long Milliseconds);
internal sealed record TransportEvidence(bool? GameAvailable, bool? VoiceAvailable, TransportProbeResult? Probe,
    IReadOnlyList<TransportStep> Steps, IReadOnlyList<TransportNetworkChange> NetworkChanges, bool? VoiceUdpVerified = null,
    int? SelectedApplications = null, JsonElement? NetworkInterfaces = null);
internal sealed record TransportCause(string Code, string Stage, string Message, string? ExceptionType, string? HResult,
    IReadOnlyList<TransportCause> Causes);
internal sealed record TransportIncident(string Id, DateTimeOffset RecordedAt, string Version, string Windows, string Vpn,
    TransportCause Primary, TransportCause? CleanupError, bool? CleanupConfirmed, TransportEvidence? Evidence);

internal sealed class TransportPreparationException(string code, Exception inner, TransportEvidence evidence,
    string? explanation = null) : IOException(code, inner)
{
    public TransportEvidence Evidence { get; } = evidence;
    public string? Explanation { get; } = explanation;
}

internal static class TransportIncidents
{
    public static string DirectoryPath => Utils.GetPath("transport-incidents");

    public static TransportCause Cause(string? code, string stage, Exception? error = null, int depth = 0)
    {
        var safe = code switch
        {
            "TRANSPORT_NO_PROFILES" => "PROFILES_UNAVAILABLE",
            "GAME_PASSIVE_SCOPE_INVALID" => "OBSERVER_SCOPE_INVALID",
            "SELECTED_APPLICATIONS_REQUIRED" or "SELECTED_APPLICATION_MISSING" or "SELECTED_APPLICATION_UNTRUSTED" or
                "SELECTED_APPLICATION_CHANGED" or "PROXY_LOOP_GUARD_INVALID" => code,
            "GAME_NOT_INSTALLED" or "AION_STEAM_NOT_FOUND" => "GAME_NOT_INSTALLED",
            "GAME_EXECUTABLE_MISSING" => "GAME_EXECUTABLE_MISSING",
            "AION_SIGNATURE_NOT_TRUSTED" or "TUN_AION_SIGNATURE_UNTRUSTED" => "GAME_SIGNATURE_UNTRUSTED",
            "VOICE_NOT_INSTALLED" or "VOICE_EXECUTABLE_MISSING" or "VOICE_SIGNATURE_UNTRUSTED" => code,
            "TUN_NON_TUN_ADDRESS_CHANGED" => "EXTERNAL_ADDRESS_CHANGED",
            "TUN_NON_TUN_ADAPTER_CHANGED" or "TUN_NON_TUN_ROUTE_CHANGED" or "TUN_NON_TUN_DNS_CHANGED" or
                "TUN_NON_TUN_INTERFACE_CHANGED" or "TUN_BASELINE_NOT_SETTLED" or "TUN_SYSTEM_PROXY_CHANGED" or
                "TUN_FIREWALL_PROFILES_CHANGED" or "TUN_LOCAL_PROXY_ROUTE_NOT_EXCLUDED" => code,
            "PROXY_AUTH_REQUIRED" or "PROXY_NOT_FOUND" or "PROXY_NOT_READY" or "PROXY_LOCAL_SOCKET_UNAVAILABLE" or
                "PROXY_UPSTREAM_UNRESPONSIVE" or "PROXY_TCP_RESPONSE_TIMEOUT" or "PROXY_UDP_RESPONSE_TIMEOUT" or
                "PROXY_UDP_ASSOCIATE_REJECTED" or "PROXY_UDP_RESPONSE_INVALID" => code,
            "DISCORD_UDP_CHAIN_NOT_VERIFIED" => "VOICE_UDP_CHAIN_NOT_VERIFIED",
            "TUN_CORE_HASH_CHANGED" or "TUN_CORE_CHECK_REJECTED" or "TUN_CORE_API_NOT_READY" or
                "TUN_CORE_EXITED_BEFORE_API" or "TUN_CORE_EXITED_DURING_ISOLATION" or "TUN_COMPONENT_STOPPED" or
                "TUN_PREFLIGHT_CONFLICT" or "TUN_EXISTING_TUN_OR_DEFAULT_NOT_PHYSICAL" or "TUN_BASELINE_AFTER_MISMATCH" => code,
            null => "UNEXPECTED_STOP",
            _ => "UNCLASSIFIED"
        };
        if (stage is "Подготовка" or "Запуск")
        {
            stage = safe switch
            {
                "PROFILES_UNAVAILABLE" or "OBSERVER_SCOPE_INVALID" or "SELECTED_APPLICATIONS_REQUIRED" or "SELECTED_APPLICATION_MISSING" or
                    "SELECTED_APPLICATION_UNTRUSTED" or "SELECTED_APPLICATION_CHANGED" => "Проверка приложений",
                "EXTERNAL_ADDRESS_CHANGED" => "Изоляция сети",
                _ when safe.StartsWith("TUN_NON_TUN_", StringComparison.Ordinal) || safe == "TUN_LOCAL_PROXY_ROUTE_NOT_EXCLUDED" => "Изоляция сети",
                _ when safe.Contains("UDP", StringComparison.Ordinal) => "Проверка UDP",
                "PROXY_TCP_RESPONSE_TIMEOUT" => "Проверка TCP",
                _ when safe.StartsWith("PROXY_", StringComparison.Ordinal) => "Проверка SOCKS5",
                _ when safe.StartsWith("TUN_CORE_", StringComparison.Ordinal) => "Запуск ядра",
                _ => stage
            };
        }
        IReadOnlyList<TransportCause> causes = [];
        if (error is not null && depth < 4)
        {
            IReadOnlyList<Exception> inner = error is AggregateException aggregate ? aggregate.InnerExceptions
                : error.InnerException is { } single ? [single] : [];
            causes = inner.Take(4).Select((e, i) => Cause(e.Message,
                error is AggregateException && i > 0 ? "Очистка" : stage, e, depth + 1)).ToArray();
        }
        return new(safe, stage, error is TransportPreparationException { Explanation: { } text } ? text :
            VaKoLinkTransport.DescribeFailure(code), error?.GetType().Name,
            error is null ? null : $"0x{error.HResult:X8}", causes);
    }

    public static TransportIncident Create(string id, string vpn, TransportCause primary, TransportCause? cleanupError,
        bool? cleanupConfirmed, TransportEvidence? evidence) =>
        new(id, DateTimeOffset.Now, typeof(TransportIncidents).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(a => a.Key == "VaKoLinkVersion")?.Value ?? "unknown", Environment.OSVersion.Version.ToString(),
            vpn, primary, cleanupError, cleanupConfirmed, evidence);

    public static void Save(TransportIncident incident)
    {
        Directory.CreateDirectory(DirectoryPath);
        var file = Path.Combine(DirectoryPath, $"transport-{incident.Id}.json");
        var temp = Path.Combine(DirectoryPath, $".{Guid.NewGuid():N}.tmp");
        try
        {
            File.WriteAllText(temp, JsonSerializer.Serialize(incident, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(temp, file, overwrite: true);
        }
        finally
        {
            if (File.Exists(temp)) File.Delete(temp);
        }
        Logging.SaveLog($"Transport: {incident.Id} {incident.Primary.Code} {incident.Primary.Stage}");
        Prune();
    }

    public static TransportIncident? ReadLatest()
    {
        try
        {
            var file = IncidentFiles().OrderByDescending(file => file.LastWriteTimeUtc).FirstOrDefault();
            return file is { Length: > 0 and < 1_000_000 }
                ? JsonSerializer.Deserialize<TransportIncident>(File.ReadAllText(file.FullName)) : null;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException) { return null; }
    }

    public static void Prune()
    {
        try
        {
            var deadline = DateTime.UtcNow.AddDays(-Math.Clamp(AppManager.Instance.Config?.VaKoLinkLogs?.TransportRetentionDays ?? 7, 1, 30));
            long retained = 0;
            foreach (var file in IncidentFiles().OrderByDescending(file => file.LastWriteTimeUtc))
            {
                retained += file.Length;
                if (file.LastWriteTimeUtc < deadline || retained > 16 * 1024 * 1024)
                    file.Delete();
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            Logging.SaveLog("Transport: не удалось очистить старые отчёты.");
        }
    }

    private static IEnumerable<FileInfo> IncidentFiles() =>
        Directory.Exists(DirectoryPath) ? new DirectoryInfo(DirectoryPath).EnumerateFiles("transport-*.json")
            .Where(file => (file.Attributes & FileAttributes.ReparsePoint) == 0 &&
                Guid.TryParseExact(Path.GetFileNameWithoutExtension(file.Name)["transport-".Length..], "N", out _)) : [];
}
