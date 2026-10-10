using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Input;
using Elka.NetworkDiagnostics.Core;
using Elka.NetworkDiagnostics.Windows;
using Microsoft.Win32;
using Record = Elka.NetworkDiagnostics.Core.Evidence;

namespace Elka.NetworkDiagnostics.App;

public sealed partial class MainViewModel
{
    private WiresharkTools? wireshark;
    private string toolsStatus = "Checking local capture tools…", packetViewerStatus = "Capture the selected flow or open a saved PCAP / PCAPNG file.", packetDetail = "Select a packet and choose Show packet details to see Wireshark's decoded headers and hex bytes.";
    private string? packetCapturePath;
    private PacketViewRow? selectedPacket;
    public ObservableCollection<PacketViewRow> Packets { get; } = [];
    public string ToolsStatus { get => toolsStatus; private set => Set(ref toolsStatus, value); }
    public string PacketViewerStatus { get => packetViewerStatus; private set => Set(ref packetViewerStatus, value); }
    public string PacketDetail { get => packetDetail; private set => Set(ref packetDetail, value); }
    public PacketViewRow? SelectedPacket { get => selectedPacket; set { if (Set(ref selectedPacket, value)) NotifyState(); } }
    public ICommand RefreshToolsCommand { get; private set; } = null!;
    public ICommand InstallCaptureToolsCommand { get; private set; } = null!;
    public ICommand CaptureNpcapCommand { get; private set; } = null!;
    public ICommand OpenCaptureCommand { get; private set; } = null!;
    public ICommand InspectPacketCommand { get; private set; } = null!;
    public ICommand OpenWiresharkCommand { get; private set; } = null!;

    private void InitializePacketViewer()
    {
        RefreshToolsCommand = Command(_ => { RefreshCaptureTools(); return Task.CompletedTask; });
        InstallCaptureToolsCommand = Command(async ct => { await InstallCaptureTools(ct); });
        CaptureNpcapCommand = Command(_ => RunAdmin("NpcapCapture"), () => wireshark != null && WiresharkTools.NpcapDetected);
        OpenCaptureCommand = Command(async ct =>
        {
            var dialog = new OpenFileDialog { Filter = "Packet captures (*.pcapng;*.pcap)|*.pcapng;*.pcap" };
            if (dialog.ShowDialog() == true) await LoadPacketCapture(dialog.FileName, external: true, ct);
        }, () => wireshark != null);
        InspectPacketCommand = Command(async ct =>
        {
            PacketDetail = await wireshark!.ReadDetail(packetCapturePath!, SelectedPacket!.Number, ct);
        }, () => wireshark != null && packetCapturePath != null && SelectedPacket != null);
        OpenWiresharkCommand = Command(_ =>
        {
            var info = new ProcessStartInfo(wireshark!.Gui) { UseShellExecute = true };
            info.ArgumentList.Add("-r"); info.ArgumentList.Add(packetCapturePath!); Process.Start(info);
            return Task.CompletedTask;
        }, () => wireshark != null && File.Exists(wireshark.Gui) && packetCapturePath != null);
        RefreshCaptureTools();
        if (App.IsPreview && App.PreviewDataRoot != null)
        {
            var preview = SessionStore.ReadOr<List<PacketViewRow>>(Path.Combine(App.PreviewDataRoot, "packet-viewer-preview.json"));
            if (preview != null)
            {
                foreach (var row in preview.Take(20)) Packets.Add(row);
                SelectedPacket = Packets.FirstOrDefault(); PacketViewerStatus = "Preview fixture · synthetic packet rows for layout validation, not a live capture.";
                PacketDetail = "Preview fixture\nEthernet II\nInternet Protocol Version 4\nUser Datagram Protocol\n    Source port: 50000\n    Destination port: 47831\n    Length: 264\nElka test payload (synthetic layout sample)";
            }
        }
    }

    private void RefreshCaptureTools()
    {
        var available = WiresharkTools.Inspect();
        wireshark = available.Tools;
        ToolsStatus = available.Message;
        NotifyState();
    }

    private async Task<bool> EnsureCaptureTools(CancellationToken ct)
    {
        try { return await InstallCaptureTools(ct, fromScan: true); }
        catch (Exception e)
        {
            if (collectingAssessment) assessment!.NpcapStatus = e is OperationCanceledException ? "setup cancelled" : "setup failed: " + e.Message.Split('\n')[0];
            throw;
        }
    }

    private async Task LoadPacketCapture(string path, bool external, CancellationToken ct)
    {
        wireshark = WiresharkTools.Find() ?? throw new InvalidOperationException("Install Wireshark with TShark first, then refresh tools.");
        // Clear the old view first: a decoder error must not leave stale packets under a new title.
        packetCapturePath = null; Packets.Clear(); SelectedPacket = null; PacketDetail = "Decoding capture…";
        PacketViewerStatus = "Reading " + Path.GetFileName(path) + "…";
        var rows = await wireshark.ReadPackets(path, ct);
        packetCapturePath = path;
        foreach (var row in rows) Packets.Add(row);
        SelectedPacket = Packets.FirstOrDefault();
        PacketViewerStatus = (external ? "External capture · not used to blame a PC. " : "Local Npcap capture · ") +
            $"{rows.Count} frame(s) displayed, limited to the first 2,000. {Path.GetFileName(path)}";
        PacketDetail = rows.Count == 0 ? "No packets were decoded. An empty capture does not prove a network block. Review capture-driver messages and the selected flow." : "Choose Show packet details for the selected frame.";
        if (!external) store.Add(Record.Create("Packet viewer", rows.Count == 0 ? Outcome.Inconclusive : Outcome.Information,
            rows.Count == 0 ? "Npcap capture contained no decoded frames." : $"Wireshark decoded {rows.Count} displayed frame(s) inside Elka.",
            "Adapter capture-point evidence only. No internal filter location or application delivery is inferred. Display is limited to the first 2,000 frames.\nSaved artifact: " + path));
        NotifyState();
    }

    private async Task<bool> InstallCaptureTools(CancellationToken ct, bool fromScan = false)
    {
        RefreshCaptureTools();
        if (wireshark != null && WiresharkTools.NpcapDetected) { Status = ToolsStatus; return true; }
        string reason = fromScan && assessment?.PacketsCaptured == false
            ? "PktMon did not produce complete packet evidence. Wireshark + Npcap can provide an independent adapter capture.\n\n"
            : "Wireshark + Npcap add an independent adapter capture to the scan.\n\n";
        string explanation = reason + ToolsStatus + $"\n\nInstall them now? Elka will download and verify the official Wireshark {WiresharkSetup.Version} x64 installer (about 98 MB; internet needed).\n\nKeep TShark selected and install Npcap when offered. Npcap adds a Windows capture driver and displays its own terms and administrator prompts. Finish and close the setup wizard; Elka will check the installation automatically" +
            (fromScan ? " and continue this scan. Choose No to finish with the available evidence." : ".") +
            "\n\nNpcap captures at the adapter; it does not expose every internal Windows layer.";
        bool NotReady(string reason)
        {
            Status = reason;
            if (collectingAssessment) assessment!.NpcapStatus = reason;
            store.Add(Record.Create("Packet viewer setup", Outcome.Inconclusive, reason, ToolsStatus));
            return false;
        }
        if (MessageBox.Show(explanation, "Set up Wireshark + Npcap", MessageBoxButton.YesNo, MessageBoxImage.Information, MessageBoxResult.No) != MessageBoxResult.Yes)
            return NotReady("Npcap capture skipped: installation was declined.");
        string installer = await WiresharkSetup.Download(store.Root, text => Status = text, ct);
        ct.ThrowIfCancellationRequested();
        // Only the pinned, signature-verified official installer can reach this launch.
        await WiresharkSetup.Verify(installer, ct);
        using var installerProcess = Process.Start(new ProcessStartInfo(installer) { UseShellExecute = true }) ?? throw new IOException("Wireshark setup could not start.");
        store.Add(Record.Create("Packet viewer setup", Outcome.Information, "Verified Wireshark installer opened for local setup.", $"Wireshark {WiresharkSetup.Version}; SHA-256 {WiresharkSetup.Sha256}. Waiting for setup to close before checking the installed components."));
        Status = "Complete the Wireshark + Npcap setup wizard and close it. Elka is waiting to check the installed tools.";
        try { await installerProcess.WaitForExitAsync(ct); }
        catch (OperationCanceledException)
        {
            // Never kill a driver installer mid-installation when the user cancels the scan.
            NotReady("Elka stopped waiting for setup. Finish any open installer, then refresh tools and rerun Packet tracing.");
            throw;
        }
        RefreshCaptureTools();
        if (wireshark == null || !WiresharkTools.NpcapDetected)
            return NotReady($"Setup closed (exit {installerProcess.ExitCode}), but required capture components are still missing.");
        Status = "Wireshark and Npcap files detected. Capture will now check driver access" + (fromScan ? " and repeat the paired tests." : ".");
        store.Add(Record.Create("Packet viewer setup", Outcome.Information, "Required Wireshark and Npcap files detected after setup.", ToolsStatus + $" Installer exit code: {installerProcess.ExitCode}. If Windows requested a reboot, complete it before retrying a failed driver capture."));
        return true;
    }
}
