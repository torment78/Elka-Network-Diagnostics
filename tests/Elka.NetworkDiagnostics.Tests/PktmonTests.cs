using Elka.NetworkDiagnostics.Core;
using Elka.NetworkDiagnostics.Windows;

internal static class PktmonTests
{
    private const string Headers = "[00]A17C.9FE8::2026-10-10 01:10:29.600089000 [MSNT_SystemTrace] Event: Header, BufferSize: 16777216\n" +
        "[00]A17C.9FE8::2026-10-10 01:10:29.600089000 [MSNT_SystemTrace] Event: PartitionInfoExtensionV2\n" +
        "[00]A17C.9FE8::2026-10-10 01:10:29.600089000 [MSNT_SystemTrace] Event: PartitionInfoExtensionV2\n";
    private const string Packet = "[00]1234.5678::2026-10-10 01:10:30.000000000 PktGroupId 42, PktNumber 1, Appearance 1, Direction Rx, Type Ethernet, Component 7, Edge 1, Filter 0, OriginalSize 298, LoggedSize 128\n";

    public static async Task Run(string root, Action<bool, string> check, Func<Func<Task>, string, Task> throws)
    {
        PktmonTextInspection Inspect(string text, int limit = 64 * 1024 * 1024) => PktmonText.Inspect(new StringReader(text), limit);
        check(!Inspect(Headers).HasPacketRecords, "real-world header-only PktMon shape cannot count as packet evidence");
        check(!Inspect("").HasPacketRecords && !Inspect("PktGroupId PktNumber summary").HasPacketRecords, "empty text and field headings remain incomplete");
        check(Inspect(Headers + Packet).SnapshotRecords == 1, "packet snapshots are recognized after trace headers");
        check(Inspect(Packet + Packet.Replace("PktGroupId", "Drop: PktGroupId")).SnapshotRecords == 2, "flow and drop snapshots count as observations, not unique packets");
        check(Inspect(Packet.Replace("42,", "0x2a,")).HasPacketRecords, "hexadecimal packet group identifiers are supported");
        check(!Inspect("PktGroupId 42\nPktNumber 1").HasPacketRecords, "unrelated lines cannot manufacture a snapshot");
        check(Inspect(Headers + Packet, Headers.Length - 1) is { HasPacketRecords: false, LimitReached: true }, "bounded analysis does not invent records beyond its limit");
        var large = PktmonText.Inspect(new RepeatedTextReader(new string('x', 1023) + "\n", 66 * 1024, Packet));
        check(!large.LimitReached && large.SnapshotRecords == 1, "PktMon inspection reaches packet evidence beyond the former 64 MiB text limit");
        var malformed = PktmonText.Inspect(new RepeatedTextReader("x", TraceTextReader.LineLimit + 1, Packet));
        check(malformed.LimitReached && malformed.LimitReason.Contains("line exceeded") && malformed.SnapshotRecords == 0, "oversized lines stop safely with an explicit reason");
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await throws(() => Task.FromResult(PktmonText.Inspect(new StringReader(Packet), cancellationToken: cancellation.Token)), "packet text inspection honors cancellation");
        await throws(() => Task.FromResult(UdpPacketTrace.Read(new StringReader(Packet), [], cancellationToken: cancellation.Token)), "UDP correlation honors cancellation");
        check(!PktmonText.Inspect(new StringReader(Packet.TrimEnd('\n')), Packet.Length - 1).LimitReached, "unterminated final line at exact input limit is fully inspected");

        var empty = new Scenario(root, Headers);
        await empty.Run();
        check(empty.Messages.Last().Kind == "inconclusive" && empty.Messages.All(m => m.Kind != "done"), "empty capture never signals successful packet evidence");
        check(empty.Commands.Contains("counters") && empty.Commands.IndexOf("counters") < empty.Commands.IndexOf("stop"), "counters are collected before stopping the owned capture");
        check(empty.StartArguments.SkipWhile(a => a != "--file-size").Skip(1).First() == "64", "circular trace has room for multiple 16 MiB Windows ETW buffers");
        check(empty.Messages.Any(m => m.Text.StartsWith("PktMon capture diagnostics\n") && m.Text.Contains("counters (exit 0)") && m.Text.Contains("etl2txt --stats (exit 0)")), "status and counters reach the UI/support summary without requiring an exported ZIP");
        check(empty.TerminalArtifactExisted, "diagnostics are persisted before the terminal IPC message");
        string transcript = await File.ReadAllTextAsync(empty.Diagnostics);
        check(new[] { "pktmon status", "pktmon list", "pktmon counters", "--stats", "Exit code:" }.All(transcript.Contains), "saved diagnostics retain capture state, components, counters and command outcomes");

        var populated = new Scenario(root, Packet);
        await populated.Run();
        check(populated.Messages.Last().Kind == "done" && populated.Messages.Last().Text.Contains("correlation still require"), "populated capture completes with explicit flow-correlation limits");

        var denied = new Scenario(root, Packet) { Fail = "start" };
        await throws(denied.Run, "capture start failure propagates");
        check(!denied.Commands.Contains("stop") && File.Exists(denied.Diagnostics), "rejected start preserves other capture and saves diagnostics");

        var badStatus = new Scenario(root, Packet) { Fail = "status" };
        await throws(badStatus.Run, "capture status failure propagates before test traffic is started");
        check(badStatus.Commands.Contains("stop") && badStatus.Messages.All(m => m.Kind != "ready"), "unverified capture cannot announce readiness and owned session is stopped");

        var disconnected = new Scenario(root, Packet) { FailReady = true };
        await throws(disconnected.Run, "capture readiness callback failure propagates");
        check(disconnected.Commands.Count(c => c == "stop") == 1, "owned capture stops even if readiness delivery fails");

        var counterFailure = new Scenario(root, Packet) { Throw = "counters" };
        await throws(counterFailure.Run, "unexpected counters failure propagates");
        check(counterFailure.Commands.Contains("stop"), "counter collection failure still stops the owned capture");

        var badConversion = new Scenario(root, Packet) { Fail = "etl2txt convert" };
        await badConversion.Run();
        check(badConversion.Messages.Last().Kind == "inconclusive" && badConversion.Messages.Any(m => m.Artifact == badConversion.Path), "conversion failure retains ETL and cannot pass tracing");

        var badStop = new Scenario(root, Packet) { Fail = "stop" };
        await throws(badStop.Run, "failed capture stop is surfaced");
        check(badStop.Messages.All(m => m.Kind != "done"), "cleanup failure cannot produce a successful capture verdict");
    }

    private sealed class Scenario(string root, string text)
    {
        public string Path { get; } = System.IO.Path.Combine(root, Guid.NewGuid() + "-pktmon.etl");
        public string Diagnostics => System.IO.Path.ChangeExtension(Path, ".diagnostics.txt");
        public List<string> Commands { get; } = [];
        public string[] StartArguments { get; private set; } = [];
        public List<HelperMessage> Messages { get; } = [];
        public string? Fail { get; init; }
        public string? Throw { get; init; }
        public bool FailReady { get; init; }
        public bool TerminalArtifactExisted { get; private set; }
        public async Task Run()
        {
            var capture = new PktmonCapture(async args =>
            {
                string key = args[0] == "etl2txt" ? args.Contains("--stats") ? "etl2txt stats" : "etl2txt convert" : args[0];
                Commands.Add(key);
                if (key == Throw) throw new IOException("Simulated command failure");
                if (key == Fail) return new(1, "", "Simulated failure: " + key);
                if (key == "start") { StartArguments = args.ToArray(); await File.WriteAllTextAsync(Path, "ETL fixture"); }
                if (key == "etl2txt convert") await File.WriteAllTextAsync(System.IO.Path.ChangeExtension(Path, ".txt"), text, System.Text.Encoding.Unicode);
                return new(0, "Fixture output for " + key, "");
            }, () => Task.CompletedTask);
            await capture.Run(Path, message =>
            {
                Messages.Add(message);
                if (message.Kind == "ready" && FailReady) throw new IOException("Disconnected reader");
                if (message.Kind is "done" or "inconclusive") TerminalArtifactExisted = File.Exists(Diagnostics);
                return Task.CompletedTask;
            });
        }
    }
}
