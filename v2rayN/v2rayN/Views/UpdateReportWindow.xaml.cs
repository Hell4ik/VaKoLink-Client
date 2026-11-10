namespace v2rayN.Views;

public partial class UpdateReportWindow
{
    public UpdateReportWindow(string clientStatus, IReadOnlyList<string> components, string? notice)
    {
        InitializeComponent();
        appStatus.Text = Capitalize(clientStatus);
        componentRows.ItemsSource = components.Select(ComponentRow.FromReport).ToArray();
        installNotice.Text = notice ?? string.Empty;
        noticeCard.Visibility = notice is null ? Visibility.Collapsed : Visibility.Visible;
        SourceInitialized += (_, _) => WindowsUtils.SetDarkBorder(this, AppManager.Instance.Config.UiItem.CurrentTheme);
    }

    private static string Capitalize(string value) =>
        value.Length == 0 ? value : char.ToUpper(value[0], CultureInfo.CurrentCulture) + value[1..];

    private sealed record ComponentRow(string Name, string Status)
    {
        internal static ComponentRow FromReport(string report)
        {
            var parts = report.Split(" — ", 2, StringSplitOptions.None);
            return parts.Length == 2
                ? new ComponentRow(parts[0], Capitalize(parts[1]))
                : new ComponentRow(string.Empty, Capitalize(report));
        }
    }
}
