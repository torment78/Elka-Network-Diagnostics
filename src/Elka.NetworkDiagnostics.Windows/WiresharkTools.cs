using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Elka.NetworkDiagnostics.Core;
using Microsoft.Win32;

namespace Elka.NetworkDiagnostics.Windows;

public record PacketViewRow(int Number, string Time, string Source, string Destination, string Protocol, int Length, string Info)
{
    public string Label => $"#{Number}  {Protocol}  {Source} → {Destination}  {Length} bytes";
}

public record CaptureToolStatus(WiresharkTools? Tools, bool NpcapInstalled, string Message)
{
    public bool CanCapture => Tools != null && NpcapInstalled;
}

public record WiresharkTools(string Directory)
{
    public string Tshark => Path.Combine(Directory, "tshark.exe");
    public string Dumpcap => Path.Combine(Directory, "dumpcap.exe");
    public string Gui => Path.Combine(Directory, "Wireshark.exe");
    public static bool NpcapDetected => NpcapFiles.All(File.Exists);
    private static IEnumerable<string> NpcapFiles => new[] { "Npcap/wpcap.dll", "Npcap/Packet.dll", "drivers/npcap.sys" }
        .Select(path => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), path));
    public static WiresharkTools? Find()
    {
        return Inspect().Tools;
    }

    public static CaptureToolStatus Inspect() => Inspect(InstallationDirectories(), NpcapDetected, File.Exists);
    public static CaptureToolStatus Inspect(IEnumerable<string> directories, bool npcapInstalled, Func<string, bool> exists)
    {
        var paths = directories.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        string? complete = paths.FirstOrDefault(path => exists(Path.Combine(path, "tshark.exe")) && exists(Path.Combine(path, "dumpcap.exe")));
        List<string> missing = [];
        if (complete == null)
        {
            if (!paths.Any(path => exists(Path.Combine(path, "tshark.exe")))) missing.Add("Wireshark TShark decoder");
            if (!paths.Any(path => exists(Path.Combine(path, "dumpcap.exe")))) missing.Add("Wireshark Dumpcap capture tool");
            if (missing.Count == 0) missing.Add("TShark and Dumpcap in the same installation folder");
        }
        if (!npcapInstalled) missing.Add("Npcap driver and capture libraries");
        return new(complete == null ? null : new(complete), npcapInstalled, missing.Count == 0
            ? $"Wireshark tools found: {complete}. Npcap files detected; live capture will verify driver access."
            : "Missing: " + string.Join("; ", missing) + ". Use Set up Wireshark + Npcap to install them.");
    }

    private static IEnumerable<string> InstallationDirectories()
    {
        // Only machine-wide installation locations; never PATH, HKCU, or a peer-supplied executable.
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            string? location = null;
            try
            {
                using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var key = machine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark");
                location = key?.GetValue("InstallLocation") as string;
            }
            catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException) { }
            if (location != null && Path.IsPathFullyQualified(location)) yield return location;
        }
        foreach (var root in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
            yield return Path.Combine(Environment.GetFolderPath(root), "Wireshark");
    }

    public async Task<IReadOnlyList<PacketViewRow>> ReadPackets(string path, CancellationToken ct = default)
    {
        ValidateCapture(path);
        var result = await Commands.Run(Tshark, ["-n", "-r", path, "-c", "2000", "-T", "fields", "-E", "separator=/t", "-E", "quote=n", "-E", "escape=y", "-E", "occurrence=f",
            "-e", "frame.number", "-e", "frame.time_relative", "-e", "ip.src", "-e", "ipv6.src", "-e", "ip.dst", "-e", "ipv6.dst",
            "-e", "_ws.col.Protocol", "-e", "frame.len", "-e", "_ws.col.Info"], ct, outputLimit: 2_000_000);
        if (result.ExitCode != 0) throw new IOException("Wireshark could not decode the capture.\n" + result.Combined);
        return ParseRows(result.Output);
    }

    public async Task<string> ReadDetail(string path, int number, CancellationToken ct = default)
    {
        ValidateCapture(path);
        if (number is < 1 or > 2000) throw new ArgumentOutOfRangeException(nameof(number));
        var result = await Commands.Run(Tshark, ["-n", "-r", path, "-c", number.ToString(CultureInfo.InvariantCulture), "-Y", "frame.number == " + number.ToString(CultureInfo.InvariantCulture), "-V", "-x"], ct);
        if (result.ExitCode != 0) throw new IOException("Wireshark could not decode this frame.\n" + result.Combined);
        return result.Output;
    }

    public static List<PacketViewRow> ParseRows(string text)
    {
        if (text.Length > 2_000_000 || text.Contains("[Output truncated", StringComparison.Ordinal)) throw new InvalidDataException("Packet listing exceeded the display limit. Keep the capture for Wireshark inspection.");
        List<PacketViewRow> rows = [];
        foreach (string line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var f = line.TrimEnd('\r').Split('\t');
            if (f.Length != 9 || !int.TryParse(f[0], NumberStyles.None, CultureInfo.InvariantCulture, out int number) || number is < 1 or > 2000 ||
                !int.TryParse(f[7], NumberStyles.None, CultureInfo.InvariantCulture, out int length) || length < 0)
                throw new InvalidDataException("Unrecognized Wireshark field output. No partial listing was accepted.");
            static string Clean(string value) => value.Replace("\\t", " ", StringComparison.Ordinal).Replace("\\n", " ", StringComparison.Ordinal).Replace("\\r", " ", StringComparison.Ordinal);
            rows.Add(new(number, f[1], Clean(f[2] == "" ? f[3] : f[2]), Clean(f[4] == "" ? f[5] : f[4]), Clean(f[6]), length, Clean(f[8])));
            if (rows.Count > 2000) throw new InvalidDataException("Too many packet rows.");
        }
        if (rows.Select(r => r.Number).Distinct().Count() != rows.Count) throw new InvalidDataException("Duplicate frame numbers in the packet listing.");
        return rows;
    }

    private static void ValidateCapture(string path)
    {
        if (!File.Exists(path) || new FileInfo(path).Length > 100 * 1024 * 1024) throw new InvalidDataException("Choose a capture file under 100 MB.");
    }
}

public sealed class NpcapCapture
{
    public static string Filter(HelperRequest request)
    {
        if (!IPAddress.TryParse(request.Address, out var local) || local.AddressFamily != AddressFamily.InterNetwork ||
            !IPAddress.TryParse(request.PeerAddress, out var peer) || peer.AddressFamily != AddressFamily.InterNetwork || request.Port is < 1024 or > 65535)
            throw new InvalidDataException("Select both literal IPv4 addresses and a valid test port for Npcap capture.");
        return $"(tcp or udp) and host {local} and host {peer} and port {request.Port}";
    }

    public static string[] Arguments(HelperRequest request, string path) =>
        ["-i", @"\Device\NPF_{" + Guid.Parse(request.AdapterId).ToString("D") + "}", "-p", "-f", Filter(request),
         "-s", "1600", "-a", "duration:25", "-a", "filesize:16384", "-c", "10000", "-w", path];

    public async Task Run(HelperRequest request, string path, WiresharkTools tools, Func<HelperMessage, Task> emit,
        Func<string, IReadOnlyList<string>, string, Func<Task>, Task<CommandResult>>? capture = null)
    {
        string logPath = Path.ChangeExtension(path, ".diagnostics.txt");
        string[] args = Arguments(request, path);
        string log = $"Npcap / Wireshark capture\nStarted: {DateTimeOffset.UtcNow:u}\nExecutable: {tools.Dumpcap}\nArguments: {string.Join(' ', args)}\n";
        try
        {
            var result = await (capture ?? RunProcess)(tools.Dumpcap, args, path,
                () => emit(new("ready", "Npcap capture started on the selected adapter for up to 25 seconds. Testing the selected address pair and port.", path)));
            log += $"Exit code: {result.ExitCode}\n{result.Combined}";
            if (File.Exists(path)) await emit(new("info", "Npcap capture saved. This observes the adapter capture point, not every internal Windows layer or application delivery.", path));
            if (result.ExitCode != 0) throw new IOException("Npcap capture could not complete. " + result.Combined);
            if (!File.Exists(path)) throw new IOException("Capture process returned without creating a capture file.");
        }
        catch (Exception e) { log += "\nError: " + e.Message; throw; }
        finally
        {
            await File.WriteAllTextAsync(logPath, log);
            await emit(new("info", "Npcap capture command, exit status and capture-driver messages saved.", logPath));
        }
        await emit(new("done", "Npcap capture process completed. Open Packet viewer for decoded packets; an empty capture remains missing evidence.", path));
    }

    private static async Task<CommandResult> RunProcess(string executable, IReadOnlyList<string> args, string path, Func<Task> ready)
    {
        var info = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string argument in args) info.ArgumentList.Add(argument);
        using var process = Process.Start(info) ?? throw new IOException("Wireshark capture process could not start.");
        var output = Commands.ReadBounded(process.StandardOutput); var errors = Commands.ReadBounded(process.StandardError);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        try
        {
            // dumpcap creates its output after opening the interface. Do not start a retest
            // merely because an installer or a process was launched.
            while (!process.HasExited && !File.Exists(path)) await Task.Delay(100, timeout.Token);
            if (!process.HasExited && File.Exists(path)) await ready();
            await process.WaitForExitAsync(timeout.Token);
            return new(process.ExitCode, await output, await errors);
        }
        finally
        {
            if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(); }
            await Task.WhenAll(output, errors);
        }
    }
}
