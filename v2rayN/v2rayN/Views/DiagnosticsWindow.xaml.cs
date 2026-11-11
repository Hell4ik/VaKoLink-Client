using System.Windows;

namespace v2rayN.Views;

public sealed record DiagnosticRow(string Name, string State);

public partial class DiagnosticsWindow
{
    private readonly string _report;

    public DiagnosticsWindow(string version, IReadOnlyList<DiagnosticRow> states)
    {
        InitializeComponent();
        rows.ItemsSource = states;
        _report = string.Join(Environment.NewLine, states.Select(row => $"{row.Name}: {row.State}")
            .Prepend($"VaKoLink v{version} · {RuntimeInformation.ProcessArchitecture}"));
        SourceInitialized += (_, _) => WindowsUtils.SetDarkBorder(this, AppManager.Instance.Config.UiItem.CurrentTheme);
    }

    private void CopyReport_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(_report);
            copyReport.Content = "Скопировано";
        }
        catch (ExternalException)
        {
            copyReport.Content = "Повторить копирование";
        }
    }
}
