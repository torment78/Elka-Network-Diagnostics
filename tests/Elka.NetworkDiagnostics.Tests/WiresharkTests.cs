using Elka.NetworkDiagnostics.Core;
using Elka.NetworkDiagnostics.Network;
using Elka.NetworkDiagnostics.Windows;

internal static class WiresharkTests
{
    public static async Task Run(string root, Action<bool, string> check, Func<Func<Task>, string, Task> throws, string? toolsDirectory)
    {
        string installFolder = Path.Combine(root, "installed-tools"), decoderOnly = Path.Combine(root, "incomplete-tools");
        HashSet<string> installed = [Path.Combine(installFolder, "tshark.exe"), Path.Combine(installFolder, "dumpcap.exe"), Path.Combine(decoderOnly, "tshark.exe")];
        check(!WiresharkTools.Inspect([installFolder], false, installed.Contains).CanCapture, "decoder tools without the Npcap driver cannot qualify for live capture");
        var partial = WiresharkTools.Inspect([decoderOnly], true, installed.Contains);
        check(!partial.CanCapture && partial.Message.Contains("Dumpcap"), "incomplete Wireshark installation identifies its missing capture executable");
        check(WiresharkTools.Inspect([decoderOnly, installFolder], true, installed.Contains).Tools?.Directory == installFolder, "complete installation can be found after an incomplete candidate");
        check(WiresharkTools.Inspect([installFolder], true, installed.Contains).CanCapture, "complete component set can proceed to actual driver verification");

        List<string> visited = []; List<string> failures = []; bool ready = false;
        await PacketTracingWorkflow.Run(action => { visited.Add(action); if (action == "PacketCapture") throw new IOException("Empty capture"); return Task.CompletedTask; },
            () => { visited.Add("setup"); ready = true; return Task.FromResult(ready); }, (action, _) => failures.Add(action), default);
        check(visited.SequenceEqual(["WfpAudit", "PacketCapture", "setup", "NpcapCapture"]) && failures.SequenceEqual(["PacketCapture"]), "failed PktMon still offers setup and runs Npcap after setup completes");
        visited.Clear();
        await PacketTracingWorkflow.Run(action => { visited.Add(action); return Task.CompletedTask; },
            () => { visited.Add("setup declined"); return Task.FromResult(false); }, (_, _) => { }, default);
        check(visited.SequenceEqual(["WfpAudit", "PacketCapture", "setup declined"]), "declined or incomplete setup preserves completed checks without launching unavailable tools");
        using var cancelled = new CancellationTokenSource(); visited.Clear();
        await throws(() => PacketTracingWorkflow.Run(action => { visited.Add(action); return Task.CompletedTask; },
            () => { cancelled.Cancel(); return Task.FromResult(true); }, (_, _) => { }, cancelled.Token), "cancellation while awaiting setup is propagated");
        check(!visited.Contains("NpcapCapture"), "cancelling setup wait prevents automatic capture afterwards");

        var request = new HelperRequest("NpcapCapture", Guid.NewGuid().ToString(), 47831, "192.0.2.20", Guid.NewGuid(), "192.0.2.10");
        check(NpcapCapture.Filter(request) == "(tcp or udp) and host 192.0.2.20 and host 192.0.2.10 and port 47831", "Npcap capture is scoped to both addresses, test port and protocols");
        await throws(() => Task.FromResult(NpcapCapture.Filter(request with { PeerAddress = "192.0.2.10 or host 8.8.8.8" })), "untrusted text cannot extend a capture filter");
        await throws(() => Task.FromResult(NpcapCapture.Filter(request with { PeerAddress = "::1" })), "unsupported capture address family is rejected");
        var args = NpcapCapture.Arguments(request, Path.Combine(root, "selected.pcapng"));
        check(args.Contains("duration:25") && args.Contains("filesize:16384") && args.Contains("10000") && args.Contains("-p"), "Npcap capture is bounded and uses non-promiscuous mode");
        check(args[1] == @"\Device\NPF_{" + request.AdapterId + "}", "capture selects the adapter GUID rather than a changing interface number");
        string row = "1\t0.000000\t192.0.2.10\t\t192.0.2.20\t\tUDP\t298\t50000 → 47831 Len=256\n";
        var rows = WiresharkTools.ParseRows(row);
        check(rows.Single() is { Number: 1, Source: "192.0.2.10", Destination: "192.0.2.20", Protocol: "UDP", Length: 298 }, "Wireshark fields populate the in-app packet list");
        check(WiresharkTools.ParseRows("").Count == 0, "empty capture stays empty rather than becoming a successful observation");
        check(WiresharkTools.ParseRows("1\t0\t\t2001:db8::1\t\t2001:db8::2\tTCP\t60\tInfo\\ntext\n").Single().Source == "2001:db8::1", "offline IPv6 rows display without confusing empty IPv4 fields");
        await throws(() => Task.FromResult(WiresharkTools.ParseRows(row + "[Output truncated at 2,000,000 characters.]")), "truncated decoder output cannot fabricate a complete list");
        await throws(() => Task.FromResult(WiresharkTools.ParseRows(row + row)), "duplicate frame numbers are rejected");

        var tools = new WiresharkTools(root);
        string path = Path.Combine(root, "fake-npcap.pcapng"); List<HelperMessage> messages = [];
        await new NpcapCapture().Run(request, path, tools, m => { messages.Add(m); return Task.CompletedTask; }, async (_, _, p, ready) =>
        { await File.WriteAllTextAsync(p, "fixture"); await ready(); return new(0, "", "Packets: 0"); });
        check(messages[0].Kind == "ready" && messages.Last().Kind == "done" && File.ReadAllText(Path.ChangeExtension(path, ".diagnostics.txt")).Contains("Packets: 0"), "capture readiness and driver counts are retained without claiming observed packets");
        messages.Clear();
        await throws(() => new NpcapCapture().Run(request, path + "-failed", tools, m => { messages.Add(m); return Task.CompletedTask; }, (_, _, _, _) => Task.FromResult(new CommandResult(1, "", "Npcap driver unavailable"))), "capture driver failure propagates");
        check(messages.All(m => m.Kind is not ("ready" or "done")) && File.ReadAllText(Path.ChangeExtension(path + "-failed", ".diagnostics.txt")).Contains("driver unavailable"), "failed capture keeps diagnostics and never starts coordinated tests");
        await throws(() => WiresharkSetup.Verify(path, default), "nonmatching installer cannot pass verification");

        if (toolsDirectory == null) return;
        tools = new(toolsDirectory);
        string fixture = Path.Combine(root, "decoder-fixture.pcap");
        WriteFixture(fixture);
        var actual = await tools.ReadPackets(fixture);
        check(actual.Count == 2 && actual.All(p => p.Source == "192.0.2.10" && p.Destination == "192.0.2.20" && p.Protocol == "UDP"), "real Wireshark TShark decodes the Elka UDP fixture into in-app rows");
        string detail = await tools.ReadDetail(fixture, 2);
        check(detail.Contains("Frame 2") && detail.Contains("47831") && detail.Contains("0000"), "real TShark returns selected packet headers and hex bytes");
        string invalid = Path.Combine(root, "invalid.pcap"); await File.WriteAllTextAsync(invalid, "Not a packet capture");
        await throws(() => tools.ReadPackets(invalid), "real decoder failure cannot leave a successful packet list");
    }

    public static void WriteFixture(string path)
    {
        using var writer = new BinaryWriter(File.Create(path));
        writer.Write(0xa1b2c3d4u); writer.Write((ushort)2); writer.Write((ushort)4); writer.Write(0); writer.Write(0); writer.Write(65535u); writer.Write(1u);
        var spec = new TestSpec(Guid.NewGuid(), "00112233445566778899AABBCCDDEEFF00", "UDP", 47831, 200, 256, 5);
        byte[] frame = PacketPathTests.Frame(spec);
        for (int i = 0; i < 2; i++) { writer.Write(1_791_584_400u); writer.Write(i * 5000); writer.Write(frame.Length); writer.Write(frame.Length); writer.Write(frame); }
    }
}
