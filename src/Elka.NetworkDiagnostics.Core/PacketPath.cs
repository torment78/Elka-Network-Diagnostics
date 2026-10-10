namespace Elka.NetworkDiagnostics.Core;

public record PacketSnapshot(Guid TestId, int Sequence, int ComponentId, int Appearance, string GroupId,
    int PacketNumber, string Direction, string DropReason);
public record PathCheckpoint(string Title, string State, string Detail);
public record PacketPathFlow(string Title, string TestIdentity, List<PathCheckpoint> Checkpoints, string Observations, LocalFinding? Finding = null)
{
    public override string ToString() => Title;
}
public record PacketPathReport(Guid SessionId, DateTimeOffset Started, List<PacketPathFlow> Flows, ScanFocus? Focus = null,
    List<DirectionCheck>? Directions = null);

public static class PacketPath
{
    public static List<PacketPathFlow> Build(DiagnosticAssessment run)
    {
        List<PacketPathFlow> result = [];
        var scoped = FaultLocalization.ScopedFlows(run);
        var latest = scoped.GroupBy(f => (f.Protocol, f.Sender, f.Receiver, f.Port)).Select(g => g.Last()).ToList();
        var capturedIds = run.PacketSnapshots.Select(s => s.TestId).ToHashSet();
        // Npcap retests use new IDs after the PktMon window. Keep the latest result
        // first, but retain captured runs as separate entries with their own evidence.
        var earlierCaptures = scoped.Where(f => f.Protocol == "UDP" && f.TestId.HasValue && capturedIds.Contains(f.TestId.Value) && !latest.Contains(f))
            .GroupBy(f => f.TestId).Select(g => g.Last()).ToList();
        var flows = latest.Concat(earlierCaptures).ToList();
        foreach (var drop in FaultLocalization.ScopedDrops(run).Where(d => d.DestinationPort == run.TestPort))
            if (!flows.Any(f => f.Protocol == drop.Protocol && f.Sender == drop.Sender && f.Receiver == drop.Receiver))
                flows.Add(new(drop.Protocol, drop.Sender, drop.Receiver, run.TestPort, Outcome.Inconclusive,
                    "Capture matched this direction; no coordinated socket result was collected."));
        foreach (var flow in flows)
        {
            bool earlierCapture = earlierCaptures.Contains(flow);
            var relatedCapture = earlierCapture ? null : earlierCaptures.LastOrDefault(f =>
                f.Protocol == flow.Protocol && f.Sender == flow.Sender && f.Receiver == flow.Receiver && f.Port == flow.Port);
            var snapshots = run.PacketSnapshots.Where(s => s.TestId == flow.TestId).ToArray();
            var dropped = snapshots.Where(s => s.DropReason != "").ToArray();
            var wfp = run.Drops.Where(d => d.Protocol == flow.Protocol && d.Sender == flow.Sender && d.Receiver == flow.Receiver && d.DestinationPort == flow.Port).ToArray();
            bool sendComplete = flow.Sent.HasValue && flow.Sent == flow.Expected;
            bool deliveryComplete = flow.Received.HasValue && flow.Received == flow.Expected;
            string counts = $"{flow.Received?.ToString() ?? "unknown"}/{flow.Expected?.ToString() ?? "unknown"}";
            List<PathCheckpoint> checkpoints =
            [
                new("1  Sender application", sendComplete ? "Observed" : "Incomplete", $"Sending socket accepted {flow.Sent?.ToString() ?? "unknown"}/{flow.Expected?.ToString() ?? "unknown"} {(flow.Protocol == "UDP" ? "datagrams" : "application blocks")}. This is not proof of NIC transmission."),
                new("2  Sender network adapter", "Not observed", "A matching snapshot must be mapped to the sending NIC before this checkpoint can be confirmed."),
                new("3  Receiver network adapter", "Not observed", "A matching snapshot must be mapped to the receiving NIC. Socket delivery alone is not a NIC observation."),
                new("4  Windows components on this PC", dropped.Length > 0 ? "Drop reported" : snapshots.Length > 0 ? "Observed" : relatedCapture != null ? "Earlier capture available" : "Not observed",
                    snapshots.Length > 0 ? $"{snapshots.Length} snapshots match this UDP test's identity, addresses and destination port across {snapshots.Select(s => s.ComponentId).Distinct().Count()} component IDs. See the sample path below." :
                    relatedCapture != null ? $"This later retest has a different test ID. PktMon recorded {run.PacketSnapshots.Count(s => s.TestId == relatedCapture.TestId)} snapshots for earlier test {relatedCapture.TestId} in this direction. Select its PktMon entry above to inspect those observations separately." :
                    flow.Protocol == "TCP" ? "Per-packet TCP correlation requires stream reassembly; the current view reports application delivery only." : "No readable packet snapshots could be matched to this test. The stopping point is unknown."),
                new("5  Windows filtering", wfp.Length > 0 ? "Drop reported" : "Not established",
                    wfp.Length > 0 ? $"WFP reported {wfp.Length} drop event(s) for this flow during the audit window. Filter IDs: {string.Join(", ", wfp.Select(d => d.FilterId).Distinct())}. See the finding above for origin and ownership context. These are flow-level events, not a match to an individual sequence number." :
                    "No matching WFP drop was recorded. This does not prove that every filter allowed every packet."),
                new("6  Receiving socket", deliveryComplete ? "Observed" : "Incomplete", $"{counts} unique {(flow.Protocol == "UDP" ? "datagrams" : "application blocks")} were received and verified by the Elka test listener."),
                new("7  Application payload", deliveryComplete ? "Verified by Elka" : "Incomplete", $"Elka verified {counts} test payloads using the test identity, token, sequence and payload pattern. VBAN parsing and audio playback are not tested here.")
            ];
            string detail = "Capture scope: " + run.Adapter.Address + " only. Component IDs are local to this capture; they are not NIC names or firewall ownership.\n";
            if (earlierCapture) detail += "This is an earlier PktMon test, retained separately from the latest retest. Its socket counts and component observations belong to the test ID shown above.\n";
            if (snapshots.Length > 0)
            {
                int sequence = dropped.FirstOrDefault()?.Sequence ?? snapshots[0].Sequence;
                var sample = snapshots.Where(s => s.Sequence == sequence).OrderBy(s => s.Appearance).Take(24).ToArray();
                detail += $"Sample datagram sequence {sequence} (zero-based), test {flow.TestId}:\n" +
                    string.Join("\n", sample.Select(s => $"  Appearance {s.Appearance}: component {s.ComponentId}, {s.Direction}, group {s.GroupId}/{s.PacketNumber}" + (s.DropReason == "" ? "" : $" — reported drop: {s.DropReason}"))) +
                    "\nThe last observation is not automatically the failure location. A missing later observation can be a capture gap.\n";
            }
            if (run.PacketTraceNotes.Count > 0) detail += "\nScan-wide capture totals (may include other test IDs):\n" + string.Join("\n", run.PacketTraceNotes.Distinct());
            detail += "\nPacket checksums are not used as identity or a drop verdict; offload and capture truncation affect their interpretation.";
            string label = earlierCapture ? $" · PktMon test {flow.TestId!.Value.ToString("N")[..8]}" : " · Latest test";
            string identity = earlierCapture ? "Earlier PktMon capture · " : "Latest result · ";
            result.Add(new($"{flow.Protocol}  {flow.Sender} → {flow.Receiver}:{flow.Port}" + label,
                identity + (flow.TestId.HasValue ? $"Test {flow.TestId}" : "This attempt has no completed test identity."), checkpoints, detail, FaultLocalization.ForFlow(run, flow)));
        }
        return result;
    }

    public static string Describe(IEnumerable<PacketPathFlow> flows)
    {
        var items = flows.ToArray();
        string index = "Separate test runs retained:\n" + string.Join("\n", items.Select(f => f.Title + " — " + f.TestIdentity));
        return index + "\n\n" + string.Join("\n\n", items.Select(f =>
            f.Title + "\n" + f.TestIdentity + "\n" + (f.Finding is { } finding ? finding.Title + "\n" + finding.Evidence + "\nNext check: " + finding.NextStep + "\n" : "") +
            string.Join("\n", f.Checkpoints.Select(c => $"{c.Title}: {c.State}\n{c.Detail}")) + "\n" + f.Observations));
    }
}
