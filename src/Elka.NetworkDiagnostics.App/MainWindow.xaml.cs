using System.ComponentModel;
using System.Windows;

namespace Elka.NetworkDiagnostics.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel vm = new();
    private bool closing;
    public MainWindow()
    {
        InitializeComponent(); DataContext = vm;
        // WorkArea is already in WPF units, including the user's display scaling.
        Width = Math.Min(Width, SystemParameters.WorkArea.Width);
        Height = Math.Min(Height, SystemParameters.WorkArea.Height);
        MinWidth = Math.Min(MinWidth, SystemParameters.WorkArea.Width);
        MinHeight = Math.Min(MinHeight, SystemParameters.WorkArea.Height);
        SizeChanged += (_, _) => FitResults();
        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(vm.EvidenceExpanded) or nameof(vm.LogExpanded)) FitResults();
            if (e.PropertyName == nameof(vm.RestoreAttemptDetail) && vm.SelectedPage == 2)
                Dispatcher.BeginInvoke(new Action(() => { RestoreDetailsPanel.IsExpanded = true; RestoreDetailsPanel.BringIntoView(); }));
        };
        Closing += OnClosing; Loaded += async (_, _) => await vm.InitializeDiscovery();
    }
    private void FitResults()
    {
        bool compact = ActualHeight < 800;
        // Keep adapter controls and the stage list at their readable size. The
        // duplicate overview remains available in Protocols / Packet path.
        ScanOverview.Visibility = RunHelp.Visibility = compact ? Visibility.Collapsed : Visibility.Visible;
        int expanded = (vm.EvidenceExpanded ? 1 : 0) + (vm.LogExpanded ? 1 : 0);
        ResultsGrid.MinHeight = compact ? 160 + expanded * 70 : 290 + expanded * 90;
    }
    public void SelectPage(int page) => WorkspaceTabs.SelectedIndex = page;
    private async void OnClosing(object? sender, CancelEventArgs e)
    {
        if (closing) return;
        e.Cancel = true;
        if (vm.IsAdminRunning && MessageBox.Show("The elevated operation will continue and restore temporary settings even if this window closes. Close the window?", "Operation in progress", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        closing = true; await vm.DisposeAsync(); Close();
    }
}
