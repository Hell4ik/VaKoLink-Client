namespace VakoLink.AntiDpi.Windows;

public static class ProxyEndpointRefresh
{
    // This is only permitted before a new session. The running session still pins and verifies its original owner/configuration.
    public static LocalProxyEndpoint? PreviousListenerOrSingle(LocalProxyEndpoint previous, IReadOnlyList<LocalProxyEndpoint> fresh)
    {
        if (fresh.Count == 0) throw new IOException("PROXY_NOT_FOUND");
        if (fresh.Select(p => p.GuiPid).Distinct().Count() != 1) throw new IOException("PROXY_MULTIPLE_CLIENTS");
        var sameListener = fresh.Where(p => p.Host == previous.Host && p.Port == previous.Port).ToArray();
        if (sameListener.Length == 1) return sameListener[0];
        return fresh.Count == 1 ? fresh[0] : null;
    }
    public static string Identity(LocalProxyEndpoint p) => AionTunPlan.Hash(string.Join('|', p.Host, p.Port, p.OwnerPid,
        p.OwnerBirthUtc.ToUniversalTime().ToString("O"), p.GuiPid,
        string.Join(';', p.Members.OrderBy(m => m.Pid).Select(m => $"{m.Pid}:{m.BirthUtc.ToUniversalTime():O}:{AionTunPlan.Hash(m.Path)}")),
        string.Join(';', (p.Configurations ?? []).Select(c => c.Hash).Order(StringComparer.Ordinal))));
}
