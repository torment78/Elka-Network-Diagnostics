using System.Buffers.Binary;
using System.Net;
using Elka.NetworkDiagnostics.Core;
using Elka.NetworkDiagnostics.Network;
using Elka.NetworkDiagnostics.Windows;

internal static class PacketPathTests
{
    public static void Run(Action<bool, string> check)
    {
        var spec = new TestSpec(Guid.NewGuid(), "00112233445566778899AABBCCDDEEFF00", "UDP", 47831, 200, 256, 5);
        var flow = new FlowObservation("UDP", "192.0.2.10", "192.0.2.20", 47831, Outcome.Passed, "200/200", spec.Id, 200, 200, 200, 256);
        byte[] frame = Frame(spec);
        bool Matches(byte[] bytes, FlowObservation? test = null) => UdpPacketTrace.TryIdentify(bytes, [test ?? flow], out var id) && id == (spec.Id, 0);
        check(Matches(frame), "captured UDP identity matches the real test payload format");
        check(Matches(frame[..128]), "bounded snapshot identifies UDP without inventing full payload verification");
        check(Matches(frame[14..]), "IP-only component snapshots are supported");
        check(!Matches(frame[..80]), "snapshot truncated before the identity is not matched");
        check(!Matches(frame, flow with { TestId = Guid.NewGuid() }), "another test ID cannot match the current flow");
        check(!Matches(frame, flow with { Sender = "192.0.2.99" }) && !Matches(frame, flow with { Receiver = "192.0.2.99" }), "addresses constrain packet identity");
        check(!Matches(frame, flow with { Port = 6980 }) && !Matches(frame, flow with { PayloadSize = 128 }), "wrong destination port and datagram size are excluded");
        check(!Matches(frame, flow with { Sender = flow.Receiver, Receiver = flow.Sender }), "an echo cannot impersonate its original directional test");
        byte[] bad = (byte[])frame.Clone(); bad[23] = 6;
        check(!Matches(bad), "TCP bytes are never interpreted as UDP test packets");
        bad = (byte[])frame.Clone(); bad[20] = 0x20;
        check(!Matches(bad), "fragmented datagrams require reassembly and remain unobserved");
        bad = (byte[])frame.Clone(); bad[42] = 0;
        check(!Matches(bad), "missing ELK1 signature is rejected");
        bad = (byte[])frame.Clone(); BinaryPrimitives.WriteInt32LittleEndian(bad.AsSpan(78), 200);
        check(!Matches(bad), "out-of-range packet sequence is rejected");
        bad = (byte[])frame.Clone(); bad[14] = 0x44;
        check(!Matches(bad), "invalid IPv4 header length is rejected");
        bad = (byte[])frame.Clone(); bad[39] = 0;
        check(!Matches(bad), "inconsistent IP and UDP lengths cannot match");
        byte[] vlan = new byte[frame.Length + 4]; frame[..12].CopyTo(vlan, 0); vlan[12] = 0x81; vlan[15] = 1; frame[12..].CopyTo(vlan, 16);
        check(Matches(vlan), "802.1Q tagged IPv4 UDP identity is decoded");

        string Header(int component, int appearance, string drop = "") => $"[00]1.2::2026-10-10 00:00:00 PktGroupId 99, PktNumber 1, Appearance {appearance}, Direction Rx, Type Ethernet, Component {component}, Edge 1, Filter 0, " +
            (drop == "" ? "" : "DropReason " + drop + ", ") + "OriginalSize 298, LoggedSize 128\n";
        string Hex(byte[] bytes, bool words = false) => string.Join("\n", bytes.Chunk(16).Select((row, i) =>
            $"0x{i * 16:x4}: " + string.Join(" ", row.Chunk(words ? 2 : 1).Select(Convert.ToHexString)))) + "\n";
        UdpTraceResult Read(string text) => UdpPacketTrace.Read(new StringReader(text), [flow]);
        string text = Header(7, 1) + Hex(frame[..128]) + Header(12, 2, "31") + Hex(frame[..128], true);
        var trace = Read(text);
        check(trace.Snapshots.Count == 2 && trace.Snapshots[1].DropReason == "31", "byte and word hex dumps correlate component observations and explicit drop reasons");
        check(trace.Snapshots.Select(s => s.ComponentId).SequenceEqual([7, 12]), "same datagram identity is retained across Windows components");
        check(Read(Header(7, 1) + Hex(frame[..128]).Replace("0x0010", "0x0030")).Snapshots.Count == 0, "discontinuous hex offsets cannot fabricate payload bytes");
        check(Read(Header(7, 1) + "metadata only\n").Snapshots.Count == 0, "snapshot metadata without recognizable bytes stays uncorrelated");
        check(Read(Header(7, 1) + "[00]1.2::Next unrelated event\n" + Hex(frame)).Snapshots.Count == 0, "hex from another event cannot attach to the previous packet");
        check(Read(Header(7, 1, "0x0000") + Hex(frame[..128])).Snapshots.Single().DropReason == "", "zero drop reason does not report a drop");
        check(Read(Header(7, 1).Replace("PktGroupId", "Drop: PktGroupId") + Hex(frame[..128])).Snapshots.Single().DropReason == "unspecified reason", "explicit drop with no decoded reason remains an explicit drop");
        check(Read(Header(7, 1).Replace(",", "") + Hex(frame[..128])).Snapshots.Count == 1, "space-separated PktMon fields are decoded");
        check(Read(Header(7, 1) + Hex(frame[..128]).Replace(" 00", "  00")).Snapshots.Count == 1, "extra spacing between hex groups does not discard packet bytes");
        check(Read(Header(7, 1) + Hex(frame[..100])).Snapshots.Count == 0, "missing logged bytes keep a snapshot uncorrelated");
        check(UdpPacketTrace.Read(new StringReader(text), [flow], 10).LimitReached, "packet correlation reports analysis limits");
        string one = Header(7, 1) + Hex(frame[..128]);
        byte[] background = (byte[])frame.Clone(); Guid.NewGuid().TryWriteBytes(background.AsSpan(46, 16));
        string backgroundRecord = Header(7, 1) + Hex(background[..128]);
        var large = UdpPacketTrace.Read(new RepeatedTextReader(backgroundRecord, 133_000, one), [flow]);
        check((long)backgroundRecord.Length * 133_000 > 64 * 1024 * 1024 && !large.LimitReached && large.Snapshots.Count == 1 && large.SnapshotHeaders == 133_001 && large.Summary.Contains("to the end"),
            "UDP evidence after 133,000 background snapshots and 64 MiB of text is examined without loading the whole file");
        var limited = UdpPacketTrace.Read(new StringReader(one + one + text), [flow], snapshotLimit: 2);
        check(limited.LimitReached && limited.MatchedSnapshots == 4 && limited.SnapshotHeaders == 4 && limited.Snapshots.Count == 2,
            "detail capacity does not stop analysis of later snapshot headers and identities");
        check(limited.Snapshots.Any(s => s.DropReason == "31") && limited.LimitReason.Contains("2 matching snapshot details") && limited.LimitReason.Contains("to the end"),
            "late matched drop replaces ordinary retained detail and omission is disclosed");
        var exact = UdpPacketTrace.Read(new StringReader(one), [flow], one.Length, 1);
        check(!exact.LimitReached && exact.Snapshots.Count == 1, "exact input and detail limits do not falsely report partial analysis");
        check(UdpPacketTrace.Read(new StringReader(one), [flow], one.Length - 10).Snapshots.Count == 0, "text truncation inside hex data cannot produce a matching complete snapshot");

        var run = new DiagnosticAssessment(new("id", "Ethernet", "NIC", flow.Receiver, "255.255.255.0", "", "Up", false), flow.Sender, 47830, 47831);
        run.Flows.Add(flow); run.PacketSnapshots.AddRange(trace.Snapshots);
        var path = PacketPath.Build(run).Single();
        check(path.Checkpoints[3].State == "Drop reported" && path.Checkpoints[4].State == "Not established", "component drop is not automatically blamed on Windows Firewall");
        check(path.Checkpoints[1].State == "Not observed" && path.Checkpoints[2].State == "Not observed", "socket success or arbitrary component IDs do not prove NIC observations");
        check(path.Checkpoints[5].State == "Observed" && path.Checkpoints[6].State == "Verified by Elka", "socket and application verification remain explicit and separate");
        check(Recommendations.Analyze(run).Any(r => r.Title.Contains("component that reported")), "matched packet drops produce a component-specific review recommendation");
        run.PacketSnapshots.Add(new(Guid.NewGuid(), 0, 99, 1, "1", 1, "Rx", "foreign"));
        check(Recommendations.Analyze(run).Where(r => r.Title.Contains("component that reported")).All(r => !r.Evidence.Contains("foreign")), "unrelated test identity cannot contaminate drop recommendations");
        run.PacketSnapshots.Clear(); run.Drops.Add(new("UDP", flow.Sender, flow.Receiver, 50000, flow.Port, "789"));
        path = PacketPath.Build(run).Single();
        check(path.Checkpoints[3].State == "Not observed" && path.Checkpoints[4].Detail.Contains("flow-level"), "WFP flow evidence cannot become per-packet component proof");
        run.Flows.Add(flow with { TestId = null, Sent = null, Received = null, Outcome = Outcome.Inconclusive });
        check(PacketPath.Build(run).Single().Checkpoints[5].State == "Incomplete", "a later incomplete attempt cannot display an earlier test's socket success");
        run.Flows.Add(flow with { Sender = "192.0.2.99" });
        check(PacketPath.Build(run).Count == 1, "unrelated directional flow excluded from selected packet path");

        var sequential = new DiagnosticAssessment(run.Adapter, run.Peer, run.ControlPort, run.TestPort);
        sequential.Flows.Add(flow);
        sequential.PacketSnapshots.AddRange(trace.Snapshots);
        var later = flow with { TestId = Guid.NewGuid() };
        sequential.Flows.Add(later);
        var retained = PacketPath.Build(sequential);
        check(retained.Count == 2 && retained[0].TestIdentity.Contains(later.TestId.ToString()!) && retained[1].TestIdentity.Contains(spec.Id.ToString()),
            "a later Npcap-style retest preserves the earlier PktMon test as a separate selectable entry");
        check(retained[0].Checkpoints[3].State == "Earlier capture available" && retained[0].Checkpoints[3].Detail.Contains(spec.Id.ToString()) && !retained[0].Finding!.HasLocalDrop,
            "later test points to earlier capture without borrowing its packet observations or drop");
        check(retained[1].Title.Contains("PktMon test") && retained[1].Checkpoints[3].State == "Drop reported" && retained[1].Finding!.HasLocalDrop,
            "retained PktMon test keeps its own component observations and explicit rejection");
        string report = PacketPath.Describe(retained);
        check(report.IndexOf("PktMon test", StringComparison.Ordinal) < 1000 && report.Contains(spec.Id.ToString()) && report.Contains(later.TestId.ToString()!),
            "report index exposes both test identities before long checkpoint details");
        sequential.Flows[^1] = later with { TestId = null, Sent = null, Received = null, Outcome = Outcome.Inconclusive };
        retained = PacketPath.Build(sequential);
        check(retained[0].Checkpoints[5].State == "Incomplete" && retained[1].Checkpoints[5].State == "Observed",
            "retained successful capture cannot replace an incomplete latest socket result");
        sequential.Flows.Add(flow with { Sender = "192.0.2.99", TestId = Guid.NewGuid() });
        sequential.PacketSnapshots.Add(new(sequential.Flows[^1].TestId!.Value, 0, 99, 0, "1", 1, "Rx", "foreign"));
        check(PacketPath.Build(sequential).Count == 2, "a captured unrelated address cannot create a retained path entry");
    }

    internal static byte[] Frame(TestSpec spec)
    {
        byte[] frame = new byte[14 + 20 + 8 + spec.Size]; frame[12] = 8; frame[14] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(16), (ushort)(20 + 8 + spec.Size)); frame[22] = 64; frame[23] = 17;
        IPAddress.Parse("192.0.2.10").GetAddressBytes().CopyTo(frame, 26); IPAddress.Parse("192.0.2.20").GetAddressBytes().CopyTo(frame, 30);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(34), 50000); BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(36), (ushort)spec.Port);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(38), (ushort)(8 + spec.Size)); SocketTests.Packet(spec, 0).CopyTo(frame, 42);
        return frame;
    }

    public static void WritePreview(string directory)
    {
        Directory.CreateDirectory(directory);
        var session = new DiagnosticSession(Guid.NewGuid(), DateTimeOffset.UtcNow, "UI PREVIEW FIXTURE", "Endpoint", []);
        var run = new DiagnosticAssessment(new("preview", "Ethernet", "Preview NIC", "192.0.2.20", "255.255.255.0", "", "Up", false), "192.0.2.10", 47830, 47831);
        var test = Guid.NewGuid();
        run.Flows.Add(new("UDP", "192.0.2.10", "192.0.2.20", 47831, Outcome.Failed, "Preview sample", test, 200, 200, 197, 256));
        run.PacketSnapshots.Add(new(test, 42, 7, 1, "99", 1, "Rx", ""));
        run.PacketSnapshots.Add(new(test, 42, 12, 2, "99", 1, "Rx", "31"));
        run.PacketTraceNotes.Add("Synthetic layout fixture. These are not measurements from a real computer.");
        SessionStore.AtomicWrite(Path.Combine(directory, "session.json"), session);
        SessionStore.AtomicWrite(Path.Combine(directory, "packet-path.json"), new PacketPathReport(session.Id, run.Started, PacketPath.Build(run), FaultLocalization.Overview(run)));
        SessionStore.AtomicWrite(Path.Combine(directory, "packet-viewer-preview.json"), new[] {
            new PacketViewRow(1, "0.000000", "192.0.2.10", "192.0.2.20", "UDP", 298, "50000 → 47831 Len=256"),
            new PacketViewRow(2, "0.005000", "192.0.2.10", "192.0.2.20", "UDP", 298, "50000 → 47831 Len=256"),
            new PacketViewRow(3, "0.006000", "192.0.2.20", "192.0.2.10", "UDP", 298, "47831 → 50000 Len=256") });

        // Separate fixture for the sequential PktMon -> Npcap workflow from the report.
        string retestDirectory = Path.Combine(directory, "sequential-captures");
        Directory.CreateDirectory(retestDirectory);
        run.PacketSnapshots[1] = run.PacketSnapshots[1] with { DropReason = "" };
        run.Flows[0] = run.Flows[0] with { Outcome = Outcome.Passed, Received = 200, Detail = "Preview fixture: 200/200 delivered during PktMon capture." };
        run.Flows.Add(run.Flows[0] with { TestId = Guid.NewGuid(), Detail = "Preview fixture: later 200/200 retest during Npcap capture." });
        var reverse = run.Flows[0] with { Sender = run.Flows[0].Receiver, Receiver = run.Flows[0].Sender, TestId = Guid.NewGuid() };
        run.Flows.Add(reverse);
        run.PacketSnapshots.Add(run.PacketSnapshots[0] with { TestId = reverse.TestId!.Value, Direction = "Tx" });
        run.Flows.Add(reverse with { TestId = Guid.NewGuid(), Detail = "Preview fixture: later reverse retest during Npcap capture." });
        run.Flows.Add(run.Flows[0] with { Protocol = "TCP", TestId = Guid.NewGuid() });
        run.Flows.Add(reverse with { Protocol = "TCP", TestId = Guid.NewGuid() });
        run.PacketsCaptured = run.PacketAnalysisComplete = run.WfpCaptured = run.WfpAnalyzed = true; run.NpcapStatus = "Preview fixture: frames decoded";
        SessionStore.AtomicWrite(Path.Combine(retestDirectory, "session.json"), session);
        SessionStore.AtomicWrite(Path.Combine(retestDirectory, "packet-path.json"), new PacketPathReport(session.Id, run.Started, PacketPath.Build(run), FaultLocalization.Overview(run)));
        string partialDirectory = Path.Combine(directory, "partial-analysis");
        Directory.CreateDirectory(partialDirectory);
        run.PacketAnalysisComplete = false;
        run.PacketAnalysisStatus = "Synthetic preview: text analysis reached its limit. The remaining text was not examined.";
        run.PacketTraceNotes.Add(run.PacketAnalysisStatus);
        var recommendations = Recommendations.Analyze(run);
        var partialSession = session with { Evidence = [Evidence.Create("Recommendations and repair", Outcome.Information,
            "Preview: successful delivery with partial packet analysis", Recommendations.Report(run, recommendations))] };
        SessionStore.AtomicWrite(Path.Combine(partialDirectory, "session.json"), partialSession);
        SessionStore.AtomicWrite(Path.Combine(partialDirectory, "packet-path.json"), new PacketPathReport(session.Id, run.Started, PacketPath.Build(run), FaultLocalization.Overview(run)));
        var latest = run.Flows.GroupBy(f => (f.Protocol, f.Sender, f.Receiver)).Select(g => g.Last()).ToArray();
        run.Flows.Clear(); run.Flows.AddRange(latest);
        run.PacketSnapshots.Clear(); run.PacketTraceNotes.Clear();
        run.IsQuickCheck = true; run.IsFullScan = false;
        foreach (bool failed in new[] { false, true })
        {
            string quickDirectory = Path.Combine(directory, failed ? "two-pc-shortfall" : "two-pc-pass");
            Directory.CreateDirectory(quickDirectory);
            if (failed)
            {
                int index = run.Flows.FindIndex(f => f.Protocol == "UDP" && f.Receiver == run.Adapter.Address);
                run.Flows[index] = run.Flows[index] with { Outcome = Outcome.Failed, Received = 0, Detail = "Synthetic example: the sending socket accepted 200 datagrams; this PC verified 0." };
            }
            var quickSession = session with { Evidence = [Evidence.Create("Two-PC check", Outcome.Information, "Synthetic two-PC result",
                TwoPcCheck.Describe(TwoPcCheck.Build(run)))] };
            SessionStore.AtomicWrite(Path.Combine(quickDirectory, "session.json"), quickSession);
            SessionStore.AtomicWrite(Path.Combine(quickDirectory, "packet-path.json"), new PacketPathReport(session.Id, run.Started,
                PacketPath.Build(run), FaultLocalization.Overview(run), TwoPcCheck.Build(run)));
        }
    }
}
