using System.IO;
using System.Text.Json;
using System.Windows;
using Microsoft.Win32;
using v2rayN.Manager;

namespace v2rayN.Views;

public sealed record DiagnosticRow(string Name, string State);

public partial class DiagnosticsWindow
{
    private readonly string _report;
    private readonly TransportIncident? _incident;

    internal DiagnosticsWindow(string version, IReadOnlyList<DiagnosticRow> states, TransportIncident? incident)
    {
        InitializeComponent();
        rows.ItemsSource = states;
        _report = string.Join(Environment.NewLine, states.Select(row => $"{row.Name}: {row.State}")
            .Prepend($"VaKoLink v{version} · {RuntimeInformation.ProcessArchitecture}"));
        _incident = incident;
        saveIncident.IsEnabled = incident is not null;
        selectedIncident.Text = incident is null ? "Отчётов маршрутизации пока нет."
            : $"{incident.RecordedAt:dd.MM.yyyy HH:mm:ss} · {incident.Primary.Stage}\n{incident.Primary.Message}";
        var settings = AppManager.Instance.Config.VaKoLinkLogs ?? new();
        rotationMinutes.Text = settings.RotationMinutes.ToString();
        retentionHours.Text = settings.RetentionHours.ToString();
        transportDays.Text = settings.TransportRetentionDays.ToString();
        SourceInitialized += (_, _) => WindowsUtils.SetDarkBorder(this, AppManager.Instance.Config.UiItem.CurrentTheme);
    }

    private void OpenLogs_Click(object sender, RoutedEventArgs e) => ProcUtils.ProcessStart(Utils.GetLogPath());

    private async void SaveIncident_Click(object sender, RoutedEventArgs e)
    {
        if (_incident is not { } incident) return;
        var dialog = new SaveFileDialog
        {
            FileName = $"VaKoLink-Transport-{incident.RecordedAt:yyyyMMdd-HHmmss}.json",
            Filter = "Отчёт JSON|*.json",
        };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            await File.WriteAllTextAsync(dialog.FileName, JsonSerializer.Serialize(incident, new JsonSerializerOptions { WriteIndented = true }));
            saveIncident.Content = "Отчёт сохранён";
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            saveIncident.Content = "Повторить сохранение";
        }
    }

    private async void SaveSettings_Click(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(rotationMinutes.Text, out int rotation) || rotation is < 1 or > 1440 ||
            !int.TryParse(retentionHours.Text, out int retention) || retention is < 1 or > 168 ||
            !int.TryParse(transportDays.Text, out int days) || days is < 1 or > 30)
        {
            saveSettings.Content = "Проверьте значения";
            return;
        }
        saveSettings.IsEnabled = false;
        try
        {
            var config = AppManager.Instance.Config;
            var previous = config.VaKoLinkLogs;
            config.VaKoLinkLogs = new() { RotationMinutes = rotation, RetentionHours = retention, TransportRetentionDays = days };
            if (await ConfigHandler.SaveConfig(config) != 0)
            {
                config.VaKoLinkLogs = previous;
                saveSettings.Content = "Не удалось сохранить";
                return;
            }
            Logging.ConfigureRetention(config.VaKoLinkLogs);
            await Task.Run(() => { Logging.Prune(); TransportIncidents.Prune(); });
            saveSettings.Content = "Настройки сохранены";
        }
        finally
        {
            saveSettings.IsEnabled = true;
        }
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
