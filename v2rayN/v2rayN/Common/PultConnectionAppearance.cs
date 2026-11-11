using System.Windows.Media;

namespace v2rayN.Common;

internal enum PultConnectionAppearance
{
    Off, Proxy, Transport, Tun
}

internal static class PultConnectionAppearances
{
    internal static PultConnectionAppearance For(bool connected, bool useTun, bool transportRunning) =>
        !connected ? PultConnectionAppearance.Off : useTun ? PultConnectionAppearance.Tun
        : transportRunning ? PultConnectionAppearance.Transport : PultConnectionAppearance.Proxy;

    internal static (string Label, Color Color) Tray(this PultConnectionAppearance appearance) => appearance switch
    {
        PultConnectionAppearance.Proxy => ("Proxy подключён", Color.FromRgb(0x69, 0xD8, 0xA8)),
        PultConnectionAppearance.Transport => ("Proxy + Transport", Color.FromRgb(0xC1, 0x9C, 0xFA)),
        PultConnectionAppearance.Tun => ("TUN подключён", Color.FromRgb(0xF0, 0x82, 0x8B)),
        _ => ("Отключено", Colors.Transparent)
    };
}
