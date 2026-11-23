using System.Collections.ObjectModel;
using Microsoft.Win32;

namespace v2rayN.Views;

internal partial class TransportAppsWindow
{
    private const int Limit = 32;
    private readonly ObservableCollection<string> _applications;
    public List<string> Applications => _applications.ToList();

    public TransportAppsWindow(IEnumerable<string> items)
    {
        InitializeComponent();
        _applications = new(items.Distinct(StringComparer.OrdinalIgnoreCase));
        applications.ItemsSource = _applications;
        SourceInitialized += (_, _) => WindowsUtils.SetDarkBorder(this, AppManager.Instance.Config.UiItem.CurrentTheme);
    }

    private void Add_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = "Приложения Windows|*.exe", Multiselect = true, CheckFileExists = true };
        if (dialog.ShowDialog(this) != true) return;
        var images = dialog.FileNames.Where(path => !_applications.Contains(path, StringComparer.OrdinalIgnoreCase)).ToArray();
        if (_applications.Count + images.Length > Limit)
        {
            notice.Text = $"Можно выбрать до {Limit} приложений.";
            return;
        }
        foreach (var path in images) _applications.Add(path);
        notice.Text = string.Empty;
    }

    private void Remove_Click(object sender, RoutedEventArgs e)
    {
        foreach (var path in applications.SelectedItems.Cast<string>().ToArray()) _applications.Remove(path);
        notice.Text = string.Empty;
    }

    private void Save_Click(object sender, RoutedEventArgs e) => DialogResult = true;
}
