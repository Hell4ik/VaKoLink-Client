using System.Windows.Media;

namespace v2rayN.Common;

internal static class PultTheme
{
    public static void Apply(bool dark)
    {
        var resources = Application.Current.Resources;
        void Set(string key, uint darkRgb, uint lightRgb)
        {
            var rgb = dark ? darkRgb : lightRgb;
            var brush = new SolidColorBrush(Color.FromRgb((byte)(rgb >> 16), (byte)((rgb >> 8) & 0xFF), (byte)(rgb & 0xFF)));
            brush.Freeze();
            resources["Pult" + key] = brush;
        }

        Set("Background", 0x0D1523, 0xEDF3F9);
        Set("Header", 0x101B2B, 0xF7FAFE);
        Set("Card", 0x121E30, 0xFFFFFF);
        Set("Outline", 0x283E54, 0xCDDCEB);
        Set("Connected", 0x16382F, 0xE7F5ED);
        Set("ConnectedOutline", 0x356C57, 0x78AC91);
        Set("Control", 0x192B40, 0xE8F1FA);
        Set("ControlOutline", 0x35536D, 0xACC5DC);
        Set("Selected", 0x143653, 0xD6EAFA);
        Set("Text", 0xF3F7FC, 0x192D43);
        Set("Muted", 0xABC2DE, 0x486683);
        Set("Accent", 0x8DD8FF, 0x095984);
        Set("Good", 0x87E5BE, 0x146847);
        Set("Medium", 0xFFD274, 0x855100);
        Set("Bad", 0xFF99AA, 0xA42643);
    }
}
