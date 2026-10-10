using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace Elka.NetworkDiagnostics.App;

public partial class App : Application
{
    public static bool IsPreview { get; private set; }
    public static string? PreviewDataRoot { get; private set; }
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        IsPreview = e.Args.Contains("--render-preview");
        int previewData = Array.IndexOf(e.Args, "--preview-data");
        if (IsPreview && previewData >= 0 && previewData + 1 < e.Args.Length) PreviewDataRoot = Path.GetFullPath(e.Args[previewData + 1]);
        DispatcherUnhandledException += (_, error) =>
        {
            if (IsPreview) { File.WriteAllText(e.Args[1] + ".error.txt", error.Exception.ToString()); error.Handled = true; Shutdown(1); }
            else { MessageBox.Show(error.Exception.Message, "Elka Network Diagnostics", MessageBoxButton.OK, MessageBoxImage.Error); error.Handled = true; }
        };
        var window = new MainWindow(); MainWindow = window; window.Show();
        if (e.Args.Length >= 2 && e.Args[0] == "--render-preview")
        {
            if (e.Args.Length >= 3 && int.TryParse(e.Args[2], out int page) && page is >= 0 and <= 5) window.SelectPage(page);
            window.Dispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(() =>
            {
                window.UpdateLayout();
                if (e.Args.Contains("--preview-scroll-bottom")) { window.PacketPathScroll.ScrollToEnd(); window.UpdateLayout(); }
                var root = (FrameworkElement)window.Content;
                var bitmap = new RenderTargetBitmap((int)(root.ActualWidth + root.Margin.Left + root.Margin.Right), (int)(root.ActualHeight + root.Margin.Top + root.Margin.Bottom), 96, 96, PixelFormats.Pbgra32); bitmap.Render(window);
                var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap)); using (var stream = File.Create(e.Args[1])) encoder.Save(stream);
                Shutdown();
            }));
        }
    }
}
