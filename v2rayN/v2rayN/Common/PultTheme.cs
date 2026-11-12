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
        Set("ConnectedMode", 0x21473E, 0xCBEADD);
        Set("Transport", 0x2E2348, 0xF1EBFC);
        Set("TransportOutline", 0x654C87, 0xAC94CC);
        Set("TransportAccent", 0xDCC6FF, 0x5B3785);
        Set("TransportMode", 0x41305F, 0xE5D8F8);
        Set("Tun", 0x392429, 0xFCEEEF);
        Set("TunOutline", 0x754650, 0xCB919A);
        Set("TunAccent", 0xF5B1B7, 0x8D3145);
        Set("TunMode", 0x4C3038, 0xF5DADF);
        Set("Control", 0x192B40, 0xE8F1FA);
        Set("ControlOutline", 0x35536D, 0xACC5DC);
        Set("Selected", 0x143653, 0xD6EAFA);
        Set("ActiveRow", 0x17342F, 0xE5F5EC);
        Set("ModeTrack", 0x0F1929, 0xF0F4F9);
        Set("ConnectAction", 0x0977A9, 0x096E9B);
        Set("ConnectActionOutline", 0x29B8F4, 0x096E9B);
        Set("StopAction", 0x983C53, 0xA5324E);
        Set("StopActionOutline", 0xD77C90, 0xA5324E);
        Set("Text", 0xF3F7FC, 0x192D43);
        Set("Muted", 0xABC2DE, 0x486683);
        Set("Accent", 0x8DD8FF, 0x095984);
        Set("Good", 0x87E5BE, 0x146847);
        Set("Medium", 0xFFD274, 0x855100);
        Set("Bad", 0xFF99AA, 0xA42643);

        resources["MaterialDesign.Brush.Background"] = resources["PultBackground"];
        resources["MaterialDesign.Brush.Foreground"] = resources["PultText"];
        resources["MaterialDesign.Brush.Card.Background"] = resources["PultCard"];
        resources["MaterialDesign.Brush.Menu.Background"] = resources["PultCard"];
        resources["MaterialDesign.Brush.Selection"] = resources["PultSelected"];
        resources["MaterialDesignPaper"] = resources["PultBackground"];
        resources["MaterialDesignBody"] = resources["PultText"];
    }
}
