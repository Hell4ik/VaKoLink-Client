namespace v2rayN.Views;

public partial class WhatsNewWindow
{
    public WhatsNewWindow(string installedVersion)
    {
        InitializeComponent();
        Title = heading.Text = $"Что нового в VaKoLink v{installedVersion}";
        SourceInitialized += (_, _) => WindowsUtils.SetDarkBorder(this, AppManager.Instance.Config.UiItem.CurrentTheme);
    }

    private void Dismiss_Click(object sender, RoutedEventArgs e) => Close();
}
