using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Windows;
using Elka.NetworkDiagnostics.Core;
using Elka.NetworkDiagnostics.Windows;

namespace Elka.NetworkDiagnostics.Helper;

internal static class Program
{
    private static readonly string Root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ElkaSoft", "NetworkDiagnostics");
    private static readonly string Journal = Path.Combine(Root, "pending-recovery.json");
    private static StreamWriter? writer;
    private static readonly HashSet<string> Actions = ["CreateRestorePoint", "QosTrial", "RestartAdapter", "FlushDns", "WinsockReset", "IpReset", "WfpAudit", "PacketCapture", "NpcapCapture", "RestorePending"];
    [STAThread]
    private static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            MessageBox.Show("Open Elka.NetworkDiagnostics.exe to start the application.\n\nThis helper is started automatically from Admin tools when administrator access is needed.", "Elka Network Diagnostics helper", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        try { MainAsync(args).GetAwaiter().GetResult(); }
        catch (Exception e) { MessageBox.Show(e.Message, "Elka Network Diagnostics helper", MessageBoxButton.OK, MessageBoxImage.Error); }
    }
    private static async Task MainAsync(string[] args)
    {
        if (args.Length != 2 || !args[0].StartsWith("ElkaNetworkDiagnostics-", StringComparison.Ordinal) || args[0].Length > 100 || args[1].Length != 64) return;
        using var pipe = new NamedPipeClientStream(".", args[0], PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(15_000);
        using var reader = new StreamReader(pipe, leaveOpen: true);
        using var streamWriter = new StreamWriter(pipe, leaveOpen: true) { AutoFlush = true }; writer = streamWriter;
        await writer.WriteLineAsync(args[1]);
        string line = await reader.ReadLineAsync() ?? throw new IOException("No helper request.");
        if (line.Length > 4096) throw new InvalidDataException("Helper request is too large.");
        try
        {
            var r = Json.Read<HelperRequest>(line);
            bool needsAdapter = r.Action is not ("CreateRestorePoint" or "RestorePending");
            if (!Actions.Contains(r.Action) || (needsAdapter && (!Guid.TryParse(r.AdapterId, out _) || r.Port is < 1024 or > 65535 || !IPAddress.TryParse(r.Address, out _))) ||
                ((r.Action == "CreateRestorePoint" || RestorePoints.RequiredFor(r.Action)) && r.SessionId == Guid.Empty)) throw new InvalidDataException("Invalid predefined helper operation.");
            string description = r.Action switch
            {
                "CreateRestorePoint" => "Ask Windows to create a System Restore point before network repairs, then verify that Windows lists it. A matching point from this session can be reused for 24 hours. This can take several minutes. System Restore covers system settings, not personal-file backup. No network repair runs with this action.",
                "QosTrial" => "Temporarily disable QoS Packet Scheduler on the selected adapter for 25 seconds, then restore its original setting. Networking may briefly disconnect.",
                "RestartAdapter" => "Restart the selected adapter. This disconnects all traffic using it, including remote desktop sessions. IP configuration is saved first.",
                "FlushDns" => "Clear the Windows DNS resolver cache. This does not change DNS servers and will not fix a UDP test using literal IP addresses.",
                "WinsockReset" => "Reset the Windows Winsock catalog. A reboot is needed. VPN/security providers can be affected. This reset has no automatic rollback; a diagnostic snapshot is saved.",
                "IpReset" => "Reset Windows TCP/IP settings on this PC. Static IP, DNS and route settings can be affected. A reboot is needed. This is a system-wide repair with no automatic rollback; a snapshot is saved for manual restoration.",
                "WfpAudit" => "Export WFP state and enable packet-drop failure auditing for 25 seconds. The original audit setting is restored afterward. Capture details can contain local network and application information.",
                "PacketCapture" => $"Run a 25-second PktMon capture (128 bytes per packet, {PktmonCapture.CaptureFileMegabytes} MB circular file) using the existing PktMon filters. It can include traffic from other applications. No existing capture will be intentionally stopped.",
                "NpcapCapture" => "Use the installed Wireshark/Npcap tools to capture this adapter's TCP/UDP traffic for the selected address pair and test port, for up to 25 seconds (16 MB / 10,000 packets maximum). Captured payloads can contain application data. Only this new capture process will be stopped.",
                _ => "Restore the original setting recorded by a previous interrupted temporary operation. Review the stored action in the result afterward."
            };
            if (MessageBox.Show(description + "\n\nRun this operation locally on this PC?", "Elka Network Diagnostics — local approval", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes)
            { await Emit("cancelled", "Cancelled locally; no changes made."); return; }
            Directory.CreateDirectory(Root);
            using var operationLock = new FileStream(Path.Combine(Root, "helper.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            if (File.Exists(Journal) && r.Action != "RestorePending") throw new InvalidOperationException(RecoveryGuidance.Describe(SessionStore.ReadOr<RecoveryRecord>(Journal)));
            if (r.Action == "RestorePending") { await Restore(); await Emit("done", "Recorded temporary state restored and verified."); return; }
            var restorePoints = new RestorePoints(new WindowsSystemRestoreBackend(), Root);
            if (r.Action == "CreateRestorePoint")
            {
                await Emit("info", "Creating or verifying your Windows restore point… This can take several minutes.");
                var receipt = await restorePoints.CreateOrVerify(r.SessionId);
                await Emit("done", $"Windows restore point verified: #{receipt.Point.SequenceNumber}, {receipt.Point.Created.ToLocalTime():g}.\nName: {receipt.Point.Description}\nNetwork repairs are available for this session for 24 hours from the point's creation. Windows will be checked again before each repair.", restorePoints.ReceiptPath);
                return;
            }
            // This gate is inside the elevated helper, before any repair or recovery journal write.
            // A UI flag or saved JSON alone never authorizes a repair: check Windows each time.
            var baseline = await restorePoints.RequireFor(r.Action, r.SessionId);
            if (baseline != null) await Emit("info", $"Pre-repair restore point verified in Windows: #{baseline.Point.SequenceNumber}, {baseline.Point.Created.ToLocalTime():g}.\nName: {baseline.Point.Description}");
            string prefix = Commands.AdapterScript(r.AdapterId);
            if (r.Action is "QosTrial" or "RestartAdapter" or "WinsockReset" or "IpReset")
            {
                var snapshot = await Commands.PowerShell(prefix + "[pscustomobject]@{Adapter=($adapter | Select-Object Name,InterfaceGuid,InterfaceDescription,Status,MacAddress);IP=(Get-NetIPAddress | Select-Object InterfaceIndex,InterfaceAlias,IPAddress,PrefixLength,PrefixOrigin,SuffixOrigin,AddressFamily);Interfaces=(Get-NetIPInterface | Select-Object InterfaceIndex,InterfaceAlias,AddressFamily,Dhcp,InterfaceMetric,NlMtu);Routes=(Get-NetRoute | Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric,Protocol,PolicyStore);Bindings=(Get-NetAdapterBinding -Name $adapter.Name -AllBindings | Select-Object ComponentID,Enabled);Dns=(Get-DnsClientServerAddress | Select-Object InterfaceIndex,AddressFamily,ServerAddresses)} | ConvertTo-Json -Depth 6");
                Require(snapshot);
                using var verifiedSnapshot = System.Text.Json.JsonDocument.Parse(snapshot.Output);
                string file = CapturePath("before-" + r.Action, ".json"); await File.WriteAllTextAsync(file, snapshot.Output); await Emit("info", "Original configuration snapshot saved.", file);
            }
            switch (r.Action)
            {
                case "QosTrial":
                    var before = await Commands.PowerShell(prefix + "(Get-NetAdapterBinding -Name $adapter.Name -ComponentID ms_pacer).Enabled | ConvertTo-Json"); Require(before);
                    bool enabled = Json.Read<bool>(before.Output.Trim());
                    if (!enabled) { await Emit("done", "QoS was already disabled. No setting was changed."); return; }
                    SessionStore.AtomicWrite(Journal, new RecoveryRecord(r.Action, r.AdapterId, enabled, null, DateTimeOffset.UtcNow));
                    try
                    {
                        Require(await Commands.PowerShell(prefix + "Disable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_pacer -Confirm:$false; if ((Get-NetAdapterBinding -Name $adapter.Name -ComponentID ms_pacer).Enabled) { throw 'QoS did not disable.' }"));
                        await Emit("ready", "QoS is temporarily disabled. Run the same test now; automatic restoration follows in 25 seconds."); await Task.Delay(25_000);
                    }
                    finally { await Restore(); }
                    break;
                case "RestartAdapter":
                    Require(await Commands.PowerShell(prefix + "Restart-NetAdapter -Name $adapter.Name -Confirm:$false"));
                    await Emit("info", "Adapter restart requested. Reconnect the endpoint and rerun the failed test.");
                    break;
                case "FlushDns":
                    Require(await Commands.PowerShell("Clear-DnsClientCache")); await Emit("info", "DNS resolver cache cleared."); break;
                case "WinsockReset":
                case "IpReset":
                    SessionStore.AtomicWrite(Journal, new RecoveryRecord(r.Action, r.AdapterId, null, null, DateTimeOffset.UtcNow, true));
                    var reset = await Commands.Run(Commands.SystemTool("netsh.exe"), r.Action == "WinsockReset" ? ["winsock", "reset"] : ["int", "ip", "reset", CapturePath("ip-reset", ".log")]);
                    await Emit("info", reset.Combined); Require(reset);
                    await Emit("info", "Restart Windows manually when ready. The saved session will reopen; this repair will not run again automatically."); break;
                case "WfpAudit":
                    string state = CapturePath("wfp-state", ".xml");
                    Require(await Commands.Run(Commands.SystemTool("netsh.exe"), ["wfp", "show", "state", "file=" + state])); await Emit("info", "WFP state exported. Registered filters alone do not establish a packet drop.", state);
                    uint flags = AuditPolicy.Get();
                    SessionStore.AtomicWrite(Journal, new RecoveryRecord(r.Action, r.AdapterId, null, flags, DateTimeOffset.UtcNow));
                    DateTimeOffset start = DateTimeOffset.UtcNow;
                    try
                    {
                        AuditPolicy.Set(AuditPolicyState.IncludeFailure(flags));
                        await Emit("ready", "WFP packet-drop failure auditing is active for 25 seconds. Send traffic now."); await Task.Delay(25_000);
                        string stamp = start.UtcDateTime.ToString("O"), endStamp = DateTimeOffset.UtcNow.UtcDateTime.ToString("O");
                        var events = await Commands.PowerShell($"try {{ $events = @(Get-WinEvent -FilterHashtable @{{LogName='Security';Id=5152;StartTime=[datetime]'{stamp}';EndTime=[datetime]'{endStamp}'}} -ErrorAction Stop) }} catch {{ if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {{ $events = @() }} else {{ throw }} }}; if ($events.Count -eq 0) {{ 'No 5152 event was returned during this capture. This does not rule out filtering.' }} else {{ $events | ForEach-Object {{ $_.ToXml() }} }}");
                        Require(events); string file = CapturePath("wfp-drop-events", ".txt"); await File.WriteAllTextAsync(file, events.Output);
                        await Emit("info", events.Output, file);
                    }
                    finally { await Restore(); }
                    // Collect the second state only after audit restoration has been verified.
                    // Missing ownership metadata must not discard the actual drop events.
                    string afterState = CapturePath("wfp-state-after", ".xml");
                    try
                    {
                        Require(await Commands.Run(Commands.SystemTool("netsh.exe"), ["wfp", "show", "state", "file=" + afterState]));
                        await Emit("info", "WFP state after the audit window exported for runtime-ID comparison.", afterState);
                    }
                    catch (Exception e) { await Emit("info", "WFP ownership comparison unavailable: " + e.Message); }
                    break;
                case "PacketCapture":
                    string path = CapturePath("pktmon", ".etl");
                    await new PktmonCapture().Run(path, message => Emit(message.Kind, message.Text, message.Artifact));
                    return;
                case "NpcapCapture":
                    var wireshark = WiresharkTools.Find() ?? throw new InvalidOperationException("Install Wireshark with TShark and Npcap first, using Packet viewer setup.");
                    await new NpcapCapture().Run(r, CapturePath("npcap", ".pcapng"), wireshark, message => Emit(message.Kind, message.Text, message.Artifact));
                    return;
            }
            await Emit("done", "Operation finished. Review the evidence and rerun the original failed test.");
        }
        catch (Exception e) { await Emit("error", e.Message + (File.Exists(Journal) ? " A recovery record remains; review it before another repair." : "")); }
    }
    private static async Task Restore()
    {
        if (!File.Exists(Journal)) throw new InvalidOperationException("There is no pending recovery record.");
        var record = Json.Read<RecoveryRecord>(await File.ReadAllTextAsync(Journal));
        if (record.RebootRequired) throw new InvalidOperationException("This record is for a network reset. Reboot and retest, then acknowledge it in the app. A reset cannot be automatically undone.");
        if (record.Action == "QosTrial" && record.OriginalEnabled.HasValue)
        {
            string cmd = record.OriginalEnabled.Value ? "Enable" : "Disable";
            var restored = await Commands.PowerShell(Commands.AdapterScript(record.AdapterId) + $"{cmd}-NetAdapterBinding -Name $adapter.Name -ComponentID ms_pacer -Confirm:$false; (Get-NetAdapterBinding -Name $adapter.Name -ComponentID ms_pacer).Enabled | ConvertTo-Json"); Require(restored);
            if (Json.Read<bool>(restored.Output.Trim()) != record.OriginalEnabled) throw new IOException("QoS restoration readback failed.");
        }
        else if (record.Action == "WfpAudit" && record.AuditFlags.HasValue) AuditPolicy.Set(record.AuditFlags.Value);
        else throw new InvalidDataException("Unknown recovery operation. Record was preserved.");
        File.Delete(Journal); await Emit("info", "Original temporary setting restored and verified.");
    }
    private static void Require(CommandResult result) { if (result.ExitCode != 0) throw new IOException(result.Combined); }
    private static string CapturePath(string name, string extension)
    {
        string folder = Path.Combine(Root, "captures"); Directory.CreateDirectory(folder);
        return Path.Combine(folder, $"{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}-{name}{extension}");
    }
    private static async Task Emit(string kind, string text, string? artifact = null)
    {
        // A closed UI must not prevent rollback. Keep running the bounded operation locally.
        try { if (writer != null) await writer.WriteLineAsync(Json.Write(new HelperMessage(kind, text, artifact))); }
        catch (IOException) { }
    }
}
