namespace Elka.NetworkDiagnostics.Core;

public record ScanFocus(string Title, string Traffic, string Capture, string Detail);
public record LocalFinding(string Title, string Evidence, string NextStep, int NextStage, bool HasLocalDrop = false);

public static class FaultLocalization
{
    public static FlowObservation[] ScopedFlows(DiagnosticAssessment run) => run.Flows.Where(f => f.Port == run.TestPort &&
        ((f.Sender == run.Adapter.Address && f.Receiver == run.Peer) || (f.Sender == run.Peer && f.Receiver == run.Adapter.Address))).ToArray();

    public static PacketDrop[] ScopedDrops(DiagnosticAssessment run) => run.Drops.Where(d =>
        (d.SourcePort == run.TestPort || d.DestinationPort == run.TestPort) &&
        ((d.Sender == run.Adapter.Address && d.Receiver == run.Peer) || (d.Sender == run.Peer && d.Receiver == run.Adapter.Address))).ToArray();

    public static ScanFocus Overview(DiagnosticAssessment run)
    {
        var flows = ScopedFlows(run);
        string Protocol(string protocol)
        {
            var items = flows.Where(f => f.Protocol == protocol).ToArray();
            if (items.Any(f => f.Outcome == Outcome.Failed))
                return protocol + ": " + (items.Where(f => f.Outcome == Outcome.Failed).All(f => f.Expected > 0 && f.Received == f.Expected) ? "completion error in " : "send/delivery failed in ") + string.Join("; ", items.Where(f => f.Outcome == Outcome.Failed)
                    .Select(f => $"{f.Sender} → {f.Receiver}").Distinct());
            bool both = new[] { (run.Adapter.Address, run.Peer), (run.Peer, run.Adapter.Address) }
                .All(pair => items.Any(f => f.Sender == pair.Item1 && f.Receiver == pair.Item2 && f.Outcome == Outcome.Passed));
            return protocol + (both && items.All(f => f.Outcome == Outcome.Passed) ? ": passed both directions" : ": tests incomplete");
        }
        string traffic = Protocol("UDP") + "\n" + Protocol("TCP");
        string capture = "Capture: WFP " + (run.WfpCaptured && run.WfpAnalyzed ? "collected" : "incomplete") + "; PktMon " +
            (run.PacketsCaptured ? $"recorded, {run.PacketSnapshots.Count} matching UDP snapshots retained; " +
                (run.PacketAnalysisComplete ? "exported text fully examined" : "analysis incomplete — see recommendations") : "incomplete") +
            "; Npcap " + run.NpcapStatus + ". Capture availability does not change a measured socket result.";
        if (run.IsQuickCheck) capture = "Scope: UDP/TCP tests between both PCs. Local Windows inspections and captures have not run.";
        bool localDrop = ScopedDrops(run).Length > 0 || run.PacketSnapshots.Any(s => s.DropReason != "" && flows.Any(f => f.TestId == s.TestId));
        if (localDrop) return new($"Focus: this PC ({run.Adapter.Address}) has a recorded drop", traffic, capture,
            "Open the affected direction below for the local rejection and next check. A recorded drop may affect only some traffic; keep any successful test results too.");
        var failures = flows.Where(f => f.Outcome == Outcome.Failed).ToArray();
        if (failures.Length > 0)
        {
            var focus = TwoPcCheck.FailureFocus(failures, run.Adapter.Address);
            return new(focus.Title, traffic, capture, focus.Detail);
        }
        bool passedBoth = new[] { "UDP", "TCP" }.All(p => Protocol(p).EndsWith("passed both directions", StringComparison.Ordinal));
        return new(passedBoth ? "Test traffic passed — no blocked PC identified" : "General checks: finish the two-PC tests", traffic, capture,
            passedBoth ? "These addresses and this test port worked. If the original application fails, test its actual flow. Missing capture evidence is a separate diagnostic issue."
            : "Start both endpoints and run all checks. Local inspections still work when pairing is unavailable; an unfinished exchange is not proof of a blocked PC.");
    }

    public static LocalFinding ForFlow(DiagnosticAssessment run, FlowObservation flow)
    {
        var drops = run.PacketSnapshots.Where(s => s.TestId == flow.TestId && s.DropReason != "").ToArray();
        var wfp = ScopedDrops(run).Where(d => d.Protocol == flow.Protocol && d.Sender == flow.Sender && d.Receiver == flow.Receiver && d.DestinationPort == flow.Port).ToArray();
        string evidence = string.Join("\n", drops.Take(4).Select(s => $"Sequence {s.Sequence}: component {s.ComponentId}, {s.Direction}; {s.DropReason}."));
        if (wfp.Length > 0)
        {
            evidence += (evidence == "" ? "" : "\n") + string.Join("\n\n", wfp.Take(4).Select(Describe));
            return new("Windows filtering reported a local rejection", evidence,
                "Inspect Windows filtering on this PC. Use the recorded origin and any matching filter context to review the specific rule or service. A provider name alone is not proof that its software is defective. Keep the failed flow unchanged for the retest.", 6, true);
        }
        if (drops.Any(s => s.DropReason.Equals("INET: transport endpoint was not found", StringComparison.OrdinalIgnoreCase)))
            return new("Windows could not find a receiving socket", evidence,
                "Inspect Ports and applications on this PC, then repeat with the receiver ready. Check the exact destination address and port. Elka's test listener closes after its bounded test, so a later port listing cannot prove what was listening at the drop time. This reason does not by itself identify a firewall block.", 4, true);
        if (drops.Length > 0) return new("A Windows component reported a local packet drop", evidence,
            "Inspect NIC bindings and drivers, then compare the component ID with this capture's PktMon inventory. The reporting component and drop reason narrow the investigation; an unresolved ID does not name the responsible driver or firewall.", 5, true);
        if (flow.Outcome == Outcome.Passed) return new("This test reached the receiving application", flow.Detail,
            "Keep this successful result. If the original application still fails, repeat its actual address, port and configuration. Capture gaps do not turn successful delivery into a failure.", 0);
        if (flow.Expected > 0 && flow.Received == flow.Expected) return new("Data arrived; review completion errors",
            flow.Detail + "\n" + flow.SendError + "\n" + flow.ReceiveError,
            "The receiver verified all expected data. Review acknowledgement and completion errors, then repeat Check both PCs. This is not evidence that the receiving socket blocked the test data.", flow.Protocol == "UDP" ? 2 : 3);
        if (flow.Outcome == Outcome.Inconclusive) return new("The test exchange is incomplete", flow.Detail,
            "Review the recorded preparation or communication error and repeat Check both PCs. Any known send count is retained; an unavailable receiver result is not a zero-delivery measurement.", flow.Protocol == "UDP" ? 2 : 3);
        if (flow.Expected > 0 && flow.Sent.HasValue && flow.Sent < flow.Expected) return new("Sending or connecting did not complete", flow.Detail + "\n" + flow.SendError,
            "Review the sending error and receiver readiness. A send/connect failure can involve either PC or the path; compare the two-PC results before investigating a Windows layer.", flow.Protocol == "UDP" ? 2 : 3);
        return new("The stopping point has not yet been observed", flow.Detail,
            "Run Packet tracing on the receiving PC while this direction is tested, and compare the sender's capture. A final visible snapshot is not automatically the drop location. If the capture is empty, inspect its saved status, counters and errors first.", 7);
    }

    public static string Describe(PacketDrop drop)
    {
        string value = $"WFP 5152: {drop.Protocol} {drop.Sender}:{drop.SourcePort} → {drop.Receiver}:{drop.DestinationPort}; filter {drop.FilterId}.";
        if (drop.Time.HasValue) value += $" Event time {drop.Time:u}.";
        if (drop.FilterOrigin != "") value += "\nEvent filter origin: " + drop.FilterOrigin + ".";
        if (drop.LayerId != "") value += " Layer ID: " + drop.LayerId + ".";
        if (drop.InterfaceIndex != "") value += " Interface index: " + drop.InterfaceIndex + ".";
        if (drop.Context is { } context)
            value += $"\nMatching before/after state: {context.Name}; layer {context.Layer}; action {context.Action}.\nProvider: {context.Provider}; service: {context.Service}; callout: {context.Callout}. State snapshots corroborate this runtime ID, but do not prove that it remained unchanged between snapshots.";
        else value += "\nFilter ownership was not corroborated by state snapshots surrounding this event. No product is blamed from the runtime ID alone.";
        return value + "\nThis event matches the flow, not an individual test sequence.";
    }
}
