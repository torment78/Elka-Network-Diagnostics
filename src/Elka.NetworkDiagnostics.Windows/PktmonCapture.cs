using System.Text;
using System.Text.RegularExpressions;
using Elka.NetworkDiagnostics.Core;

namespace Elka.NetworkDiagnostics.Windows;

public record PktmonTextInspection(int SnapshotRecords, bool LimitReached)
{
    public bool HasPacketRecords => SnapshotRecords > 0;
    public string LimitReason { get; init; } = "";
}

public static class PktmonText
{
    // Snapshot fields do not establish a unique packet count or a selected flow.
    private static readonly Regex Snapshot = new(@"\bPktGroupId\s+(?:0x)?[0-9a-f]+\s*,?\s+PktNumber\s+\d+\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    public static PktmonTextInspection Inspect(TextReader reader, long characterLimit = TraceTextReader.CharacterLimit,
        CancellationToken cancellationToken = default)
    {
        var input = new TraceTextReader(reader, characterLimit, cancellationToken);
        int count = 0;
        foreach (string line in input.Lines())
        {
            if (Snapshot.IsMatch(line)) count++;
        }
        return new(count, input.LimitReason != "") { LimitReason = input.LimitReason };
    }
}

public sealed class PktmonCapture
{
    // PktMon uses 16 MiB ETW buffers on current Windows. A 16 MiB circular file
    // reproduced header-only traces even while counters increased. Leave room
    // for data buffers as well as the header; keep the bounded capture exportable.
    public const int CaptureFileMegabytes = 64;
    private readonly Func<IReadOnlyList<string>, Task<CommandResult>> run;
    private readonly Func<Task> wait;

    public PktmonCapture() : this(args => Commands.Run(Commands.SystemTool("pktmon.exe"), args, seconds: 20), () => Task.Delay(25_000)) { }
    public PktmonCapture(Func<IReadOnlyList<string>, Task<CommandResult>> run, Func<Task> wait)
    { this.run = run; this.wait = wait; }

    public async Task Run(string path, Func<HelperMessage, Task> emit)
    {
        string diagnostics = Path.ChangeExtension(path, ".diagnostics.txt");
        var transcript = new StringBuilder($"PktMon capture diagnostics\nStarted: {DateTimeOffset.UtcNow:u}\nWindows: {Environment.OSVersion}\n");
        var summary = new StringBuilder($"PktMon capture diagnostics\nWindows: {Environment.OSVersion}\nCircular capture limit: {CaptureFileMegabytes} MB; snapshot: 128 bytes; duration: 25 seconds.\n");
        async Task<CommandResult> Execute(params string[] args)
        {
            transcript.AppendLine($"\n{DateTimeOffset.UtcNow:u} pktmon {string.Join(' ', args)}");
            try
            {
                var result = await run(args);
                transcript.AppendLine($"Exit code: {result.ExitCode}\n{result.Combined}");
                if (args[0] is "start" or "status" or "counters" or "stop" || args.Contains("--stats"))
                {
                    int limit = args[0] == "counters" ? 5000 : 1800;
                    summary.AppendLine($"\n{args[0]}{(args.Contains("--stats") ? " --stats" : "")} (exit {result.ExitCode})\n" +
                        (result.Combined.Length <= limit ? result.Combined : result.Combined[..limit] + "\n[More output in the saved diagnostics file.]"));
                }
                return result;
            }
            catch (Exception e) { transcript.AppendLine(e.Message); throw; }
        }
        static void Require(CommandResult result) { if (result.ExitCode != 0) throw new IOException(result.Combined); }
        HelperMessage completion;
        try
        {
            var filters = await Execute("filter", "list"); Require(filters);
            await emit(new("info", "Capture uses these existing filters:\n" + filters.Output));
            await Execute("list", "--all", "--include-hidden");
            var inventory = await Execute("list", "--json");
            if (inventory.ExitCode == 0)
            {
                string inventoryPath = Path.ChangeExtension(path, ".components.json");
                await File.WriteAllTextAsync(inventoryPath, inventory.Output);
                await emit(new("info", "PktMon component inventory saved for this capture. IDs can change after a driver restart; names alone do not establish a packet drop.", inventoryPath));
            }
            var start = await Execute("start", "--capture", "--comp", "all", "--type", "all", "--flags", "0x032",
                "--pkt-size", "128", "--log-mode", "circular", "--file-size", CaptureFileMegabytes.ToString(System.Globalization.CultureInfo.InvariantCulture), "--file-name", path);
            Require(start); // A rejected start must never stop somebody else's capture.
            try
            {
                Require(await Execute("status"));
                await emit(new("ready", "PktMon capture started for 25 seconds. Run the failing flow now.", path));
                await wait();
                await Execute("counters");
            }
            finally { Require(await Execute("stop")); }

            await Execute("etl2txt", path, "--stats");
            string textPath = Path.ChangeExtension(path, ".txt");
            var convert = await Execute("etl2txt", path, "--out", textPath, "--hex");
            await emit(new("info", "PktMon ETL saved. Saving a file alone does not establish that packets were recorded.", path));
            if (convert.ExitCode != 0)
                completion = new("inconclusive", "PktMon ETL was saved, but text conversion failed. Packet evidence is incomplete. Review the saved PktMon diagnostics.", diagnostics);
            else
            {
                await emit(new("info", "PktMon text is available alongside the ETL for evidence review.", textPath));
                using var reader = new StreamReader(textPath);
                var inspection = PktmonText.Inspect(reader);
                completion = inspection.HasPacketRecords
                    ? new("done", $"PktMon contains {(inspection.LimitReached ? "at least " : "")}{inspection.SnapshotRecords} readable packet snapshot records. " +
                        (inspection.LimitReached ? "Partial text inspection: " + inspection.LimitReason + " " : "Exported text inspected to the end. ") +
                        "A packet may appear at multiple components. Address, port, direction and NIC-to-socket correlation still require review.", textPath)
                    : new("inconclusive", "PktMon ran, but no readable packet snapshot records were found" +
                        (inspection.LimitReached ? " within the analysis limit" : " in the exported text") +
                        ". The capture may be empty or use an unrecognized format. This does not prove packet loss or a healthy network. Review the saved status, components, counters and ETL statistics; then retry Packet tracing while the test traffic is running.", diagnostics);
            }
        }
        finally
        {
            await File.WriteAllTextAsync(diagnostics, transcript.ToString());
            await emit(new("info", summary.ToString(), diagnostics));
        }
        // Publish the terminal result only after the artifact is safely on disk.
        await emit(completion);
    }
}
