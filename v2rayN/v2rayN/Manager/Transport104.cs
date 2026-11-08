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
            return "Для запуска Transport подключите режим Proxy.";
        }
        if (!Utils.IsAdministrator())
        {
            return "Для Transport запустите VaKoLink от имени администратора.";
        }
#if VAKOLINK_TRANSPORT
        return null;
#else
        return "Эта сборка не содержит VaKoLink Transport 1.0.4.";
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
        try
        {
            return await Task.Run<ITransportSession>(async () =>
            {
                var platform = new LocalTransportPlatform(Environment.ProcessId, port);
                var prepared = await platform.PrepareAsync((_, _) => { });
                return new Session(platform.Create(prepared));
            });
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(ProxyTunSession.SafeCode(ex), ex);
        }
#else
        await Task.CompletedTask;
        throw new InvalidOperationException("Эта сборка не содержит VaKoLink Transport 1.0.4.");
#endif
    }

#if VAKOLINK_TRANSPORT
    private sealed class Session(IUserTransportRun run) : ITransportSession
    {
        public Task StartAsync() => Task.Run(run.StartAsync);
        public Task StopAsync() => Task.Run(run.StopAsync);

        public TransportState Read()
        {
            var state = run.Read();
            var canRelease = !state.Running && (!state.CoreCreated || state.CoreExited)
                && (state.Cleanup || state.CanExitWithPendingAudit);
            return new TransportState(state.Running, canRelease, state.Cleanup, state.Failure);
        }
    }
#endif
}
