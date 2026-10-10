using System.ComponentModel;
using System.Windows;

namespace Elka.NetworkDiagnostics.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel vm = new();
    private bool closing;
    public MainWindow() { InitializeComponent(); DataContext = vm; Closing += OnClosing; Loaded += async (_, _) => await vm.InitializeDiscovery(); }
    public void SelectPage(int page) => WorkspaceTabs.SelectedIndex = page;
    private async void OnClosing(object? sender, CancelEventArgs e)
    {
        if (closing) return;
        e.Cancel = true;
        if (vm.IsAdminRunning && MessageBox.Show("The elevated operation will continue and restore temporary settings even if this window closes. Close the window?", "Operation in progress", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        closing = true; await vm.DisposeAsync(); Close();
    }
}
