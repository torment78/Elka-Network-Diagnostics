namespace Elka.NetworkDiagnostics.Core;

public record DirectionCheck(string Protocol, string Direction, string Sender, string Receiver,
    string Send, string Receive, string Result, string Detail)
{
    public bool NeedsAttention => Result is not ("Delivered" or "Not tested");
}

public static class TwoPcCheck
{
    // Roles are deliberately absent: address, direction and actual results decide
    // what was observed. Unknown control/receiver results must never become loss.
    public static List<DirectionCheck> Build(DiagnosticAssessment run)
    {
        var scoped = FaultLocalization.ScopedFlows(run);
        List<DirectionCheck> result = [];
        foreach (string protocol in new[] { "UDP", "TCP" })
        foreach (bool reverse in new[] { false, true })
        {
            string sender = reverse ? run.Peer : run.Adapter.Address, receiver = reverse ? run.Adapter.Address : run.Peer;
            var history = scoped.Where(f => f.Protocol == protocol && f.Sender == sender && f.Receiver == receiver).ToArray();
            var flow = history.LastOrDefault();
            string direction = reverse ? "Other PC → This PC" : "This PC → Other PC";
            if (flow == null)
            {
                result.Add(new(protocol, direction, sender, receiver, "Not measured", "Not measured", "Not tested",
                    "Start Elka on both PCs, then run Check both PCs from either one. An unavailable connection does not identify a faulty PC."));
                continue;
            }
            string sent = flow.Sent.HasValue ? $"{flow.Sent}/{flow.Expected?.ToString() ?? "?"} accepted" : "Not measured";
            string received = flow.Received.HasValue ? $"{flow.Received}/{flow.Expected?.ToString() ?? "?"} verified" : "Not measured";
            if (flow.SendError != "") sent += "; error";
            if (flow.ReceiveError != "") received += "; error";
            bool sendComplete = flow.Expected > 0 && flow.Sent == flow.Expected;
            bool receiveComplete = flow.Expected > 0 && flow.Received == flow.Expected;
            string verdict = flow.Outcome == Outcome.Inconclusive ? "Test incomplete" : flow.Outcome == Outcome.Passed ? "Delivered" :
                receiveComplete ? "Delivered; completion error" : flow.Sent.HasValue && !sendComplete ? "Send/connect incomplete" :
                flow.Received.HasValue && sendComplete ? "Delivery shortfall" : "Test failed";
            if (flow.Outcome == Outcome.Passed && history.Any(f => f.Outcome == Outcome.Failed)) verdict = "Delivered now; earlier failure";
            string detail = $"{protocol} {sender} → {receiver}:{flow.Port}\n" + flow.Detail;
            if (flow.CoordinationIssue != "") detail += "\n" + flow.CoordinationIssue;
            if (flow.SendError != "") detail += "\nSender/acknowledgement error: " + flow.SendError;
            if (flow.ReceiveError != "") detail += "\nReceiver error: " + flow.ReceiveError;
            detail += "\nSend counts describe socket acceptance. Receive counts describe verified application delivery. A shortfall does not identify a Windows layer or prove which PC caused it.";
            result.Add(new(protocol, direction, sender, receiver, sent, received, verdict, detail));
        }
        return result;
    }

    public static (string Title, string Detail) FailureFocus(IReadOnlyList<FlowObservation> failed, string localAddress = "")
    {
        if (failed.Count > 0 && failed.All(f => f.Expected > 0 && f.Received == f.Expected))
            return ("Data arrived; review completion errors", "The receiver verified all expected data. Review the sender's acknowledgement/error details and repeat Check both PCs. This is not evidence that the receiver blocked the test data.");
        if (failed.Count > 0 && failed.All(f => f.Expected > 0 && f.Sent.HasValue && f.Sent < f.Expected))
            return ("Next focus: send/connect tests", "Sending did not complete on " + string.Join(" and ", failed.Select(f => f.Sender).Distinct()) +
                ". Review the send error and receiver readiness, then run all checks on that PC. A failed TCP connection can also originate at the receiver or along the network path; it does not prove a sender fault.");
        var shortfalls = failed.Where(f => f.Expected > 0 && f.Sent == f.Expected && f.Received.HasValue && f.Received < f.Expected).ToArray();
        var receivers = shortfalls.Select(f => f.Receiver).Distinct().ToArray();
        if (shortfalls.Length == failed.Count && receivers.Length == 1)
            return ($"Next focus: receiver {receivers[0]}" + (localAddress == "" ? "" : receivers[0] == localAddress ? " (this PC)" : " (other PC)") + " — failed direction",
                "The sending socket accepted the test data, but the receiver verified fewer records. Run all checks on the receiving PC and compare captures from both PCs. This does not yet prove which PC or network device dropped the data.");
        if (shortfalls.Length == failed.Count && receivers.Length > 1)
            return ("Delivery failed in both directions", "Run all checks on each PC, one at a time, and compare the captures. One shared path problem can affect both directions; these results do not prove that both PCs are faulty.");
        return ("Next focus: compare both PCs and the failed direction", "Review each direction's send and receive results, then run all checks on each PC, one at a time. Missing or mixed results do not identify a single faulty PC.");
    }

    public static string Describe(IEnumerable<DirectionCheck> checks) => string.Join("\n\n", checks.Select(c =>
        $"{c.Protocol} · {c.Direction} ({c.Sender} → {c.Receiver})\nSend: {c.Send}; receive: {c.Receive}\n{c.Result}\n{c.Detail}"));
}
