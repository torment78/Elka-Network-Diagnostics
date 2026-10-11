using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using Elka.NetworkDiagnostics.Core;

namespace Elka.NetworkDiagnostics.Windows;

public record CommandResult(int ExitCode, string Output, string Error)
{
    public string Combined => Output + (Error.Length > 0 ? "\nErrors:\n" + Error : "");
}
public static class Commands
{
    public static string SystemTool(string name) => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), name);
    public static Task<CommandResult> PowerShell(string script, CancellationToken ct = default, int seconds = 45)
    {
        // EncodedCommand can emit CLIXML on stderr even with OutputFormat Text.
        // Pass a single fixed script argument directly (no intervening shell), and
        // agree on UTF-8 at both ends so localized Windows errors remain readable.
        string wrapped = "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); " +
            "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'; try { " + script +
            " } catch { [Console]::Error.WriteLine($_.Exception.Message); " +
            "[Console]::Error.WriteLine('Error ID: ' + $_.FullyQualifiedErrorId); " +
            "[Console]::Error.WriteLine('Category: ' + $_.CategoryInfo.Category); " +
            "$cause = $_.Exception; for ($i=0; $null -ne $cause -and $i -lt 5; $i++) { " +
            "[Console]::Error.WriteLine(('Exception: {0}; HRESULT: 0x{1:X8}; {2}' -f $cause.GetType().FullName, $cause.HResult, $cause.Message)); $cause = $cause.InnerException }; exit 1 }";
        return Run(SystemTool("WindowsPowerShell\\v1.0\\powershell.exe"),
            ["-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-Command", wrapped],
            ct, seconds, outputEncoding: Encoding.UTF8);
    }
    public static async Task<CommandResult> Run(string file, IEnumerable<string> arguments, CancellationToken ct = default, int seconds = 45, int outputLimit = 96_000, Encoding? outputEncoding = null)
    {
        if (outputLimit is < 1 or > 4_000_000) throw new ArgumentOutOfRangeException(nameof(outputLimit));
        var info = new ProcessStartInfo(file) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        if (outputEncoding != null) { info.StandardOutputEncoding = outputEncoding; info.StandardErrorEncoding = outputEncoding; }
        foreach (string argument in arguments) info.ArgumentList.Add(argument);
        using var process = Process.Start(info) ?? throw new IOException("Could not start diagnostic process.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(seconds));
        Task<string> output = ReadBounded(process.StandardOutput, outputLimit), errors = ReadBounded(process.StandardError, outputLimit);
        try { await process.WaitForExitAsync(deadline.Token); }
        catch (OperationCanceledException)
        {
            if (!process.HasExited) process.Kill(true);
            await process.WaitForExitAsync(CancellationToken.None);
            if (ct.IsCancellationRequested) throw;
            return new(-1, await output, "Diagnostic timed out.\n" + await errors);
        }
        return new(process.ExitCode, await output, await errors);
    }
    internal static async Task<string> ReadBounded(StreamReader reader, int limit = 96_000)
    {
        var text = new StringBuilder(); char[] block = new char[4096]; int n; bool truncated = false;
        while ((n = await reader.ReadAsync(block)) > 0)
        {
            int remaining = limit - text.Length;
            if (remaining > 0) text.Append(block, 0, Math.Min(n, remaining));
            if (n > remaining) truncated = true;
        }
        if (truncated) text.Append($"\n[Output truncated at {limit:N0} characters.]");
        return text.ToString();
    }
    public static string Quote(string value) => "'" + value.Replace("'", "''") + "'";
    public static string AdapterScript(string id)
    {
        Guid guid = Guid.Parse(id);
        return $"$adapter = Get-NetAdapter -IncludeHidden | Where-Object {{ $_.InterfaceGuid -and [guid]$_.InterfaceGuid -eq [guid]'{guid:D}' }} | Select-Object -First 1; if ($null -eq $adapter) {{ throw 'Selected adapter is no longer present.' }}; ";
    }
}

public sealed class WindowsDiagnostics
{
    public async Task<List<PortUse>> InspectPortUse(int controlPort, int testPort, CancellationToken ct)
    {
        if (controlPort is < 1024 or > 65535 || testPort is < 1024 or > 65535) throw new ArgumentException("Invalid diagnostic ports.");
        string script = $"$ports = @({controlPort},{testPort}); $rows = @(); $rows += @(Get-NetUDPEndpoint | Where-Object {{ $_.LocalPort -in $ports }} | ForEach-Object {{ [pscustomobject]@{{Protocol='UDP';Address=$_.LocalAddress;Port=$_.LocalPort;ProcessId=$_.OwningProcess;Process=(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} }}); $rows += @(Get-NetTCPConnection | Where-Object {{ $_.LocalPort -in $ports -and $_.State -eq 'Listen' }} | ForEach-Object {{ [pscustomobject]@{{Protocol='TCP';Address=$_.LocalAddress;Port=$_.LocalPort;ProcessId=$_.OwningProcess;Process=(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} }}); ConvertTo-Json -InputObject @($rows) -Depth 3";
        var result = await Commands.PowerShell(script, ct);
        if (result.ExitCode != 0) throw new IOException(result.Combined);
        return Json.Read<List<PortUse>>(result.Output);
    }
    public static List<AdapterInfo> Adapters() => NetworkInterface.GetAllNetworkInterfaces()
        .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
        .SelectMany(n => n.GetIPProperties().UnicastAddresses.Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
            .Select(a => new AdapterInfo(n.Id, n.Name, n.Description, a.Address.ToString(), a.IPv4Mask.ToString(), n.GetIPProperties().GatewayAddresses.FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork)?.Address.ToString() ?? "None", n.OperationalStatus.ToString(), n.Description.Contains("virtual", StringComparison.OrdinalIgnoreCase) || n.Description.Contains("VPN", StringComparison.OrdinalIgnoreCase) || n.Description.Contains("Wintun", StringComparison.OrdinalIgnoreCase))))
        .OrderByDescending(a => a.Status == "Up").ThenBy(a => a.IsVirtual).ThenByDescending(a => a.Gateway != "None").ToList();
    public async Task<Evidence> Collect(int stage, AdapterInfo adapter, string peer, int controlPort, int testPort, CancellationToken ct)
    {
        if (!IPAddress.TryParse(peer, out var peerIp) || peerIp.AddressFamily != AddressFamily.InterNetwork) peer = "";
        else peer = peerIp.ToString();
        string prefix = Commands.AdapterScript(adapter.Id);
        string selectedPorts = $"@({controlPort},{testPort},6980)";
        string name;
        string script;
        switch (stage)
        {
            case 1:
                name = "Network discovery";
                script = prefix + "'ADAPTER'; $adapter | Format-List Name,InterfaceDescription,Status,LinkSpeed,MacAddress,DriverInformation; 'IP CONFIGURATION'; Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex -Detailed | Format-List; 'INTERFACE / MTU / METRICS'; Get-NetIPInterface -InterfaceIndex $adapter.ifIndex | Format-Table -AutoSize; 'ROUTES'; Get-NetRoute -InterfaceIndex $adapter.ifIndex | Sort-Object DestinationPrefix | Format-Table -AutoSize; 'NEIGHBOUR CACHE'; Get-NetNeighbor -InterfaceIndex $adapter.ifIndex | Format-Table -AutoSize; 'DNS SERVERS'; Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex | Format-List; ";
                if (peer != "") script += $"'WINDOWS ROUTE TO PEER (UNBOUND)'; Find-NetRoute -RemoteIPAddress '{peer}' | Format-List; 'ROUTE USING SELECTED SOURCE'; Find-NetRoute -RemoteIPAddress '{peer}' -LocalIPAddress '{adapter.Address}' | Format-List;";
                break;
            case 4:
                name = "Ports and applications";
                script = $"'UDP ENDPOINTS FOR CONTROL, TEST AND VBAN PORTS'; Get-NetUDPEndpoint | Where-Object {{ $_.LocalPort -in {selectedPorts} }} | Select-Object LocalAddress,LocalPort,OwningProcess,@{{n='Process';e={{(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}}} | Format-Table -AutoSize; 'TCP ENDPOINTS'; Get-NetTCPConnection | Where-Object {{ $_.LocalPort -in {selectedPorts} -or $_.RemotePort -in {selectedPorts} }} | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Format-Table -AutoSize; 'UDP COUNTERS'; netstat -s -p udp;";
                break;
            case 5:
                name = "NIC bindings and drivers";
                script = prefix + "'BINDINGS'; Get-NetAdapterBinding -Name $adapter.Name -AllBindings | Format-Table DisplayName,ComponentID,Enabled -AutoSize; 'DRIVER PACKAGES'; Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceClass -in @('NET','NETSERVICE') } | Select-Object DeviceName,DriverProviderName,DriverVersion,InfName | Format-Table -AutoSize; 'ADAPTER ERRORS AND DISCARDS'; Get-NetAdapterStatistics -Name $adapter.Name | Format-List *; 'ADVANCED DRIVER SETTINGS (READ ONLY)'; Get-NetAdapterAdvancedProperty -Name $adapter.Name -ErrorAction Continue | Format-Table DisplayName,DisplayValue -AutoSize; 'NETWORK COMPONENTS'; netcfg -s n;";
                break;
            case 6:
                name = "Windows filtering";
                script = "'ACTIVE NETWORK PROFILES'; Get-NetConnectionProfile | Format-Table InterfaceAlias,NetworkCategory,IPv4Connectivity -AutoSize; 'EFFECTIVE FIREWALL PROFILE POLICY'; Get-NetFirewallProfile -PolicyStore ActiveStore | Format-List Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules,AllowLocalFirewallRules; 'ENABLED INBOUND RULES (FIRST 150, NOT A MATCH VERDICT)'; Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound | Select-Object -First 150 DisplayName,Action,Profile,PolicyStoreSourceType | Format-Table -AutoSize; 'PORT FILTERS (FIRST 150; APP, ADDRESS AND POLICY SCOPE ALSO MATTER)'; Get-NetFirewallPortFilter -PolicyStore ActiveStore | Where-Object { $_.Protocol -in @('TCP','UDP') } | Select-Object -First 150 Protocol,LocalPort,RemotePort | Format-Table -AutoSize;";
                break;
            case 7:
                name = "Packet tracing";
                script = "'RECENT WFP DROP EVENTS (ACCESS MAY REQUIRE ADMINISTRATOR)'; $events = Get-WinEvent -FilterHashtable @{LogName='Security';Id=5152,5157;StartTime=(Get-Date).AddMinutes(-15)} -MaxEvents 100 -ErrorAction Stop; $events | Select-Object TimeCreated,Id,Message | Format-List;";
                break;
            default: throw new ArgumentOutOfRangeException(nameof(stage));
        }
        var result = await Commands.PowerShell(script, ct);
        string details = result.Combined;
        if (stage == 1 && peer != "")
        {
            var ping = await Commands.Run(Commands.SystemTool("PING.EXE"), ["-4", "-n", "2", "-w", "1000", "-S", adapter.Address, peer], ct, 6);
            details += "\nSOURCE-BOUND ICMP TEST\n" + ping.Combined + "\nICMP failure does not prove TCP/UDP failure.";
        }
        bool complete = result.ExitCode == 0 && result.Error.Length == 0;
        return Evidence.Create(name, complete ? Outcome.Information : Outcome.Inconclusive,
            complete ? "Inspection collected; review evidence before choosing a repair." : "Inspection incomplete — see access, availability or command details.", details);
    }
    public async Task<Evidence> PathCheck(AdapterInfo adapter, string peer, CancellationToken ct)
    {
        if (!IPAddress.TryParse(peer, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork) throw new ArgumentException("Enter the peer IPv4 address first.");
        var lines = new List<string> { "IPv4 no-fragment ICMP probes. These depend on ICMP replies and do not establish UDP delivery or an exact path MTU." };
        foreach (int size in new[] { 1200, 1400, 1472 })
        {
            var r = await Commands.Run(Commands.SystemTool("PING.EXE"), ["-4", "-n", "1", "-w", "1000", "-f", "-l", size.ToString(), "-S", adapter.Address, ip.ToString()], ct, 5);
            lines.Add($"Payload {size} bytes (IPv4 packet {size + 28}):\n{r.Combined}");
        }
        var trace = await Commands.Run(Commands.SystemTool("TRACERT.EXE"), ["-4", "-d", "-h", "8", "-w", "300", ip.ToString()], ct, 12);
        lines.Add("Unbound route trace (Windows chooses the interface):\n" + trace.Combined);
        return Evidence.Create("Path and MTU", Outcome.Information, "Path probes collected; blocked ICMP can make results inconclusive.", string.Join("\n", lines));
    }
}
