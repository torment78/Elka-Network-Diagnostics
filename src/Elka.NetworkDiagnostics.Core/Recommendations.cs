namespace Elka.NetworkDiagnostics.Core;

public record FlowObservation(string Protocol, string Sender, string Receiver, int Port, Outcome Outcome, string Detail,
    Guid? TestId = null, int? Expected = null, int? Sent = null, int? Received = null, int? PayloadSize = null,
    string SendError = "", string ReceiveError = "", string CoordinationIssue = "");
public record PortUse(string Protocol, string Address, int Port, int ProcessId, string Process);
public record WfpFilterContext(string Name, string Provider, string Service, string Layer, string LayerId, string Action, string Callout);
public record PacketDrop(string Protocol, string Sender, string Receiver, int SourcePort, int DestinationPort, string FilterId,
    DateTimeOffset? Time = null, string FilterOrigin = "", string LayerId = "", string InterfaceIndex = "", WfpFilterContext? Context = null);
public record Recommendation(string Title, string Evidence, string NextStep, string? AdminAction = null);
public sealed class DiagnosticAssessment(AdapterInfo adapter, string peer, int controlPort, int testPort)
{
    public DateTimeOffset Started { get; } = DateTimeOffset.UtcNow;
    public AdapterInfo Adapter { get; } = adapter;
    public string Peer { get; } = peer;
    public int ControlPort { get; } = controlPort;
    public int TestPort { get; } = testPort;
    public bool IsFullScan { get; set; } = true;
    public bool IsQuickCheck { get; set; }
    public List<FlowObservation> Flows { get; } = [];
    public List<PortUse> Ports { get; } = [];
    public List<PacketDrop> Drops { get; } = [];
    public List<string> Incomplete { get; } = [];
    public bool WfpCaptured { get; set; }
    public bool WfpAnalyzed { get; set; }
    public bool PortsInspected { get; set; }
    public bool PacketsCaptured { get; set; }
    public bool PacketAnalysisComplete { get; set; }
    public string PacketAnalysisStatus { get; set; } = "Packet text has not been analyzed.";
    public string NpcapStatus { get; set; } = "not requested";
    public List<PacketSnapshot> PacketSnapshots { get; } = [];
    public List<string> PacketTraceNotes { get; } = [];
}

public static class Recommendations
{
    public static List<Recommendation> Analyze(DiagnosticAssessment run)
    {
        List<Recommendation> result = [];
        var local = run.Adapter;
        if (local.Status != "Up") result.Add(new("Restore the physical connection first", $"{local.Name} reported {local.Status}.", "Check the cable, switch port or Wi-Fi connection, then refresh the adapter and rerun checks before considering a Windows reset."));
        if (local.Address.StartsWith("169.254.", StringComparison.Ordinal) && !run.Peer.StartsWith("169.254.", StringComparison.Ordinal))
            result.Add(new("Review IP address assignment", $"The selected adapter has link-local address {local.Address}; the selected peer is {run.Peer}.", "Check whether this adapter should use DHCP or a static address. Check the DHCP server and physical connection before changing its configuration."));
        var occupied = run.Ports.Where(p => p.ProcessId != Environment.ProcessId &&
            (p.Port == run.ControlPort || p.Port == run.TestPort) &&
            (p.Address == local.Address || p.Address is "0.0.0.0" or "::")).ToArray();
        if (occupied.Length > 0) result.Add(new("Review other programs using a diagnostic port",
            string.Join("\n", occupied.Select(p => $"{p.Protocol} {p.Address}:{p.Port}: {p.Process} (PID {p.ProcessId})")),
            "A listener is a possible bind conflict, not proof of a packet drop. Select an unused control/test port on both PCs, or deliberately close the identified program after saving its work. No process is stopped automatically."));
        var selectedDrops = FaultLocalization.ScopedDrops(run);
        if (selectedDrops.Length > 0) result.Add(new("Review the filter that blocked the selected flow",
            string.Join("\n\n", selectedDrops.Take(8).Select(FaultLocalization.Describe)),
            "Open Packet path for the local rejection and suggested check. Review the event's filter origin and any corroborated filter, layer and provider context. Runtime IDs without that context do not name a security product. Review the exact protocol, address and port rule before proposing a change."));

        // Keep failures seen earlier in this run even if a later capture retest passes.
        // Never mix another session, imported claims or unrelated address/port tests into this assessment.
        var flows = run.Flows.Where(f => f.Port == run.TestPort &&
            ((f.Sender == local.Address && f.Receiver == run.Peer) || (f.Sender == run.Peer && f.Receiver == local.Address))).ToArray();
        var failed = flows.Where(f => f.Outcome == Outcome.Failed).ToArray();
        var packetDrops = run.PacketSnapshots.Where(s => s.DropReason != "" && flows.Any(f => f.TestId == s.TestId)).ToArray();
        if (packetDrops.Length > 0) result.Add(new("Review the component that reported a test-packet drop",
            string.Join("\n", packetDrops.Take(8).Select(s => $"UDP test {s.TestId}, sequence {s.Sequence}: local component {s.ComponentId}, reported reason {s.DropReason}.")),
            "Open Packet path for the explanation and suggested stage. A receiving-endpoint-not-found drop points to socket readiness/address/port checks. Other component IDs require the saved PktMon inventory; they do not identify a firewall or driver vendor by themselves."));
        bool ProtocolPassed(string protocol) => new[] { (local.Address, run.Peer), (run.Peer, local.Address) }
            .All(pair => flows.Any(f => f.Protocol == protocol && f.Sender == pair.Item1 && f.Receiver == pair.Item2 && f.Outcome == Outcome.Passed)) &&
            !flows.Any(f => f.Protocol == protocol && f.Outcome != Outcome.Passed);
        if (failed.Length > 0)
        {
            string evidence = string.Join("\n", failed.Select(f => $"{f.Protocol} {f.Sender} → {f.Receiver}:{f.Port}: {f.Detail}").Distinct());
            var focus = TwoPcCheck.FailureFocus(failed, run.Adapter.Address);
            result.Add(new(focus.Title, evidence, focus.Detail));
            bool udpOnly = failed.All(f => f.Protocol == "UDP" && f.Expected > 0 && f.Sent == f.Expected && f.Received.HasValue && f.Received < f.Expected) && ProtocolPassed("TCP");
            if (udpOnly && run.PortsInspected && occupied.Length == 0 && selectedDrops.Length == 0 && packetDrops.Length == 0 && run.WfpCaptured && run.WfpAnalyzed && run.PacketsCaptured && run.PacketAnalysisComplete && run.Incomplete.Count == 0)
                result.Add(new("Optional next test: temporary QoS trial", "TCP passed both ways while UDP had a measured delivery failure. No matching WFP drop was collected; this does not rule out filtering.",
                    "After reviewing the captures, create a restore point and try the 25-second QoS trial on the affected receiver. Compare the same UDP flow before, during and after automatic restoration. This is a controlled test, not a confirmed fix or a reason to disable QoS permanently.", "QosTrial"));
            if (failed.Any(f => flows.Any(other => other.Protocol == f.Protocol && other.Sender == f.Sender && other.Receiver == f.Receiver && other.Outcome == Outcome.Passed)))
                result.Add(new("The fault was intermittent during this run", "The same directional flow had both successful and failed samples.", "Keep both results. Repeat the failing application workload and inspect timestamps; a later successful retest does not erase the earlier failure."));
        }
        else if (ProtocolPassed("UDP") && ProtocolPassed("TCP"))
            result.Add(new("No network reset is justified by these socket tests", "UDP and TCP completed successfully in both directions for this address pair and test port.", "If the original application still fails, test its actual port and configuration. For VBAN, check stream name, destination/source address, format and application receive status. These results do not establish that VBAN audio or every network flow works."));
        else if (!run.IsFullScan && !run.IsQuickCheck) result.Add(new("This tracing attempt has no complete new socket result", "Only Packet tracing was requested. Its capture retests did not produce a complete result for both protocols and directions.", "Earlier test results remain in Evidence. Resolve the reported capture/recovery issue, then choose Run all checks for a new combined assessment. This message does not mean the endpoints are disconnected or that earlier tests failed."));
        else result.Add(new("Finish the missing two-PC tests", "A complete result for both directions of both protocols is unavailable.", "Start both endpoints with matching pairing codes and ports. Enter the peer IPv4 manually if discovery fails. An unfinished control exchange is not proof of UDP/TCP packet loss."));
        if (!run.IsQuickCheck && (!run.WfpCaptured || !run.PacketsCaptured))
            result.Add(new("Complete the missing packet evidence", $"WFP capture: {(run.WfpCaptured ? "collected" : "unavailable")}; PktMon: {(run.PacketsCaptured ? "readable packet records collected; flow correlation pending" : "unavailable or incomplete")}.", "Run Packet tracing and approve the local administrator requests. A declined request, access error, existing capture or file without readable packet records leaves this stage incomplete. Review the PktMon diagnostics file for capture status and counters; an empty trace does not prove packet loss or a healthy network."));
        if (run.PacketsCaptured && !run.PacketAnalysisComplete)
            result.Add(new("Review the incomplete packet analysis", run.PacketAnalysisStatus,
                "The capture contains packet records, but Elka's analysis or retained detail is incomplete. This is not evidence of network packet loss. Review Packet path and export the ZIP for the raw ETL and capture inventory. Repeat Packet tracing after a cancelled analysis; for a remaining limit, keep this capture for deeper review before a repair."));
        if (run.Incomplete.Count > 0) result.Add(new("Some checks could not finish", string.Join("\n", run.Incomplete.Distinct()), "Review the recorded errors and repeat those checks. Recommendations are limited to the evidence that was actually collected."));
        return result;
    }

    public static string Report(DiagnosticAssessment run, IReadOnlyList<Recommendation> recommendations) =>
        $"RECOMMENDED NEXT STEPS\nScope: {(run.IsQuickCheck ? "Two-PC check" : run.IsFullScan ? "Full diagnostic scan" : "Packet tracing only")}\nScan started: {run.Started:u}\nThis PC: {run.Adapter.Name} ({run.Adapter.Address})\nOther PC: {run.Peer}; control {run.ControlPort}; test {run.TestPort}\n\n" +
        DescribeOverview(run) + "\n\n" +
        string.Join("\n\n", recommendations.Select((r, i) => $"{i + 1}. {r.Title}\n\nEvidence: {r.Evidence}\n\nNext step: {r.NextStep}")) +
        "\n\nThese recommendations do not execute repairs. Review one change at a time, create a verified Windows restore point, approve locally and rerun the original failed test. Raw PktMon ETL/text is retained for inspection; NIC-to-socket correlation is not automatic.";

    private static string DescribeOverview(DiagnosticAssessment run)
    {
        var focus = FaultLocalization.Overview(run);
        return $"{focus.Title}\n{focus.Traffic}\n{focus.Capture}\n{focus.Detail}";
    }
}

public static class DiagnosticWorkflow
{
    public static async Task Run(Func<int, CancellationToken, Task> stage, Action<int, Exception> failed,
        Func<bool, Task> summarize, CancellationToken ct)
    {
        bool reachedEnd = false;
        try
        {
            for (int number = 1; number <= 7; number++)
            {
                ct.ThrowIfCancellationRequested();
                try { await stage(number, ct); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception error) { failed(number, error); }
            }
            reachedEnd = true;
        }
        finally { await summarize(reachedEnd); }
    }
}
