#if VAKOLINK_TRANSPORT
using VakoLink.AionTransport.Proxy;
using VakoLink.AntiDpi.Windows;
#endif

namespace v2rayN.Manager;

internal static class Transport104
{
    public static string? GetUnavailableReason(VaKoLinkConnection vpn)
    {
        if (!vpn.IsProxyReady)
        {
            return "Для маршрутизации приложений подключите режим Proxy.";
        }
        if (!Utils.IsAdministrator())
        {
            return "Для маршрутизации запустите VaKoLink от имени администратора.";
        }
#if VAKOLINK_TRANSPORT
        return AppManager.Instance.Config.VaKoLinkTransportApplications is { Count: > 0 }
            ? null : "Выберите приложения для маршрутизации.";
#else
        return "В этой сборке недоступна маршрутизация приложений.";
#endif
    }

    public static async Task<ITransportSession> PrepareAsync(VaKoLinkConnection vpn)
    {
        if (GetUnavailableReason(vpn) is { } reason)
        {
            throw new InvalidOperationException(reason);
        }
#if VAKOLINK_TRANSPORT
        var port = AppManager.Instance.GetLocalPort(EInboundProtocol.socks);
        AppContext.SetData("VaKoLink.Client.TransportData", Utils.GetPath("transport-data"));
        return await Task.Run<ITransportSession>(async () =>
        {
            var platform = new LocalTransportPlatform(Environment.ProcessId, port, persistMedia: false,
                selectedApplications: AppManager.Instance.Config.VaKoLinkTransportApplications?.ToArray() ?? []);
            try
            {
                var prepared = await platform.PrepareAsync((_, _) => { });
                return new Session(platform.Create(prepared), prepared.SelectedImages?.Count ?? 0);
            }
            catch (TransportProfilesException error)
            {
                throw new TransportPreparationException(error.Message, error,
                    new(false, false, Probe(platform.LastProbe), [], []),
                    "Игровой трафик: " + ProfileReason(error.GameReason) + " Голосовая связь: " + ProfileReason(error.VoiceReason));
            }
            catch (Exception error) when (error is not OperationCanceledException)
            {
                throw new TransportPreparationException(ProxyTunSession.SafeCode(error), error,
                    new(null, null, Probe(platform.LastProbe), [], []));
            }
        });
#else
        await Task.CompletedTask;
        throw new InvalidOperationException("В этой сборке недоступна маршрутизация приложений.");
#endif
    }

#if VAKOLINK_TRANSPORT
    private static string ProfileReason(string code) => code switch
    {
        "GAME_NOT_INSTALLED" or "VOICE_NOT_INSTALLED" => "поддерживаемая установка не найдена.",
        "GAME_EXECUTABLE_MISSING" or "VOICE_EXECUTABLE_MISSING" => "исполняемый файл не найден.",
        "AION_SIGNATURE_NOT_TRUSTED" or "VOICE_SIGNATURE_UNTRUSTED" => "подпись не подтверждена.",
        _ => "не удалось проверить установку."
    };

    private static TransportProbeResult? Probe(ProxyProbe? probe) => probe is null ? null :
        new(probe.Socks5, probe.TcpResponse, probe.UdpResponse, probe.DurationMs);

    private sealed class Session(IUserTransportRun run, int applicationCount) : ITransportSession
    {
        public Task StartAsync() => Task.Run(run.StartAsync);
        public Task StopAsync() => Task.Run(run.StopAsync);

        public TransportState Read()
        {
            var state = run.Read();
            var canRelease = !state.Running && (!state.CoreCreated || state.CoreExited)
                && (state.Cleanup || state.CanExitWithPendingAudit);
            var changes = (state.StartupIsolation ?? []).SelectMany(snapshot =>
                snapshot.Predicates.Where(predicate => !predicate.Passed).SelectMany(predicate =>
                    predicate.Differences.Select(change => Project($"startup-{snapshot.Snapshot}", predicate.Id, change))))
                .Concat((state.CleanupChecks ?? []).SelectMany(snapshot =>
                    (snapshot.Differences ?? []).SelectMany(category =>
                        category.Differences.Select(change => Project("cleanup", category.Category, change)))))
                .Distinct().Take(64).ToArray();
            var steps = (state.Lifecycle ?? []).GroupBy(step => step.Stage.Split('_')[0])
                .Select(group => new TransportStep(group.Key, group.First().ElapsedMs, group.Last().ElapsedMs, group.Count()))
                .Take(48).ToArray();
            var evidence = new TransportEvidence(null, null, Probe(state.StartupProxyProbe), steps, changes,
                state.VoiceUdpVerified, applicationCount);
            return new TransportState(state.Running, canRelease, state.Cleanup, state.Failure, evidence);
        }

        private static TransportNetworkChange Project(string phase, string category, NetworkFieldDifference change)
        {
            var parts = change.Row.Split(';');
            int? index = parts[0].StartsWith("interface=", StringComparison.Ordinal) &&
                int.TryParse(parts[0].AsSpan("interface=".Length), out int parsed) ? parsed : null;
            var family = parts.Length > 1 ? parts[1] switch
            {
                "family=2" or "family=IPv4" or "family=InterNetwork" => "IPv4",
                "family=23" or "family=IPv6" or "family=InterNetworkV6" => "IPv6",
                _ => null
            } : null;
            var kind = parts.Last() is "removed" or "added" ? parts.Last() : "changed";
            var field = change.Field.StartsWith("field-sha256=", StringComparison.Ordinal) ? "Other" : change.Field;
            return new(phase, category, index, family, field, kind);
        }
    }
#endif
}
