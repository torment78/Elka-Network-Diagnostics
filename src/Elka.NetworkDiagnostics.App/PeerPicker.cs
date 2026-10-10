using System.Windows;
using System.Windows.Controls;
using Elka.NetworkDiagnostics.Network;

namespace Elka.NetworkDiagnostics.App;

public sealed class PeerPicker : Window
{
    private readonly ListBox list;
    public DiscoveredPeer? Selected => list.SelectedItem as DiscoveredPeer;
    public PeerPicker(List<DiscoveredPeer> peers)
    {
        Style = (Style)FindResource(typeof(Window));
        Title = "Choose a discovered endpoint"; Width = 560; Height = 320; WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var panel = new DockPanel { Margin = new Thickness(20) };
        var heading = new TextBlock { Text = "Discovery names are unverified. The pairing code authenticates the endpoint when you connect.", Margin = new Thickness(0, 0, 0, 16) }; DockPanel.SetDock(heading, Dock.Top); panel.Children.Add(heading);
        var button = new Button { Content = "Select endpoint", Margin = new Thickness(0, 12, 0, 0) }; button.Click += (_, _) => { if (Selected != null) DialogResult = true; }; DockPanel.SetDock(button, Dock.Bottom); panel.Children.Add(button);
        list = new ListBox { ItemsSource = peers, SelectedIndex = 0 }; panel.Children.Add(list); Content = panel;
    }
}
