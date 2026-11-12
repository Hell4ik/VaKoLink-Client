using System.Windows.Controls;
using System.Windows.Input;
using v2rayN.Base;

namespace v2rayN.Views;

public partial class MainWindow
{
    private bool _nodeCommandRunning;

    private void SetupPultNodeMenu()
    {
        var menu = new ContextMenu { Style = (Style)FindResource("DefContextMenu") };
        nodeList.ContextMenu = menu;
        nodeList.ContextMenuOpening += (_, e) =>
        {
            var row = Mouse.DirectlyOver is DependencyObject element
                ? ItemsControl.ContainerFromElement(nodeList, element) as ListBoxItem : null;
            var target = (e.CursorLeft < 0 ? nodeList.SelectedItem : row?.Content) as ProfileItemModel;
            if (_nodeCommandRunning || target is null || ViewModel?.ProfilesViewModel is not { } profiles ||
                AppManager.Instance.ConnectionModes is not { Busy: false })
            {
                e.Handled = true;
                return;
            }
            if (row is { IsSelected: false } && e.CursorLeft >= 0)
            {
                nodeList.SelectedItem = target;
            }
            var selected = nodeList.SelectedItems.Cast<ProfileItemModel>().ToArray();
            menu.Items.Clear();

            MenuItem Command(string title, ReactiveCommand<RxVoid, RxVoid> command) =>
                Action(title, () => command.Execute().ToTask());

            MenuItem Action(string title, Func<Task> action)
            {
                var item = new MenuItem { Header = title };
                item.Click += async (_, _) =>
                {
                    if (_nodeCommandRunning || AppManager.Instance.ConnectionModes is not { Busy: false })
                    {
                        return;
                    }
                    _nodeCommandRunning = true;
                    profiles.SelectedProfile = target;
                    profiles.SelectedProfiles = selected;
                    try
                    {
                        await action();
                    }
                    catch (Exception error)
                    {
                        Logging.SaveLog("Действие с нодой", error);
                        MainSnackbar.MessageQueue?.Enqueue("Не удалось выполнить действие с нодой.");
                    }
                    finally
                    {
                        _nodeCommandRunning = false;
                    }
                };
                return item;
            }

            void AddGroup(string title, params MenuItem[] children)
            {
                var group = new MenuItem { Header = title };
                foreach (var child in children)
                {
                    group.Items.Add(child);
                }
                menu.Items.Add(group);
            }

            menu.Items.Add(Command("Редактировать", profiles.EditServerCmd));
            menu.Items.Add(Command("Клонировать выбранное", profiles.CopyServerCmd));
            menu.Items.Add(Command("Удалить выбранное", profiles.RemoveServerCmd));
            menu.Items.Add(new Separator());
            menu.Items.Add(Command("Выбрать ноду", profiles.SetDefaultServerCmd));
            AddGroup("Порядок", Command("В начало", profiles.MoveTopCmd), Command("Выше", profiles.MoveUpCmd),
                Command("Ниже", profiles.MoveDownCmd), Command("В конец", profiles.MoveBottomCmd));
            var groups = profiles.SubItems.Where(group => !string.IsNullOrEmpty(group.Id))
                .Select(group => Action(group.Remarks, () => profiles.MoveToGroupCmd.Execute(group).ToTask())).ToArray();
            if (groups.Length > 0)
            {
                AddGroup("Переместить в группу", groups);
            }
            AddGroup("Проверки", Command("Задержка TCP", profiles.TcpingServerCmd),
                Command("Задержка через ноду", profiles.RealPingServerCmd),
                Command("UDP", profiles.UdpTestServerCmd), Command("Скорость", profiles.SpeedServerCmd),
                Command("Комплексная проверка", profiles.MixedTestServerCmd),
                Command("Сортировать по результату", profiles.SortServerResultCmd));
        };
    }
}
