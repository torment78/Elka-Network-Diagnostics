using Elka.NetworkDiagnostics.Core;

internal static class TwoPcTests
{
    public static void Run(Action<bool, string> check)
    {
        var run = new DiagnosticAssessment(new("id", "LAN", "NIC", "192.0.2.10", "255.255.255.0", "", "Up", false), "192.0.2.20", 47830, 47831)
            { IsQuickCheck = true, IsFullScan = false };
        FlowObservation Flow(string protocol, bool reverse, int sent = 200, int received = 200) => new(protocol,
            reverse ? run.Peer : run.Adapter.Address, reverse ? run.Adapter.Address : run.Peer, 47831,
            sent == 200 && received == 200 ? Outcome.Passed : Outcome.Failed, "Fixture", Guid.NewGuid(), 200, sent, received, 256);
        var rows = TwoPcCheck.Build(run);
        check(rows.Count == 4 && rows.All(r => r.Result == "Not tested" && r.Receive == "Not measured"), "all four initial directions stay unknown before any tests");
        check(!Recommendations.Analyze(run).Any(r => r.Title.Contains("packet evidence") || r.Title.Contains("tracing attempt")), "quick checks do not report intentionally unrequested captures as failures");
        foreach (string protocol in new[] { "UDP", "TCP" }) foreach (bool reverse in new[] { false, true }) run.Flows.Add(Flow(protocol, reverse));
        check(TwoPcCheck.Build(run).All(r => r.Result == "Delivered" && r.Send == "200/200 accepted" && r.Receive == "200/200 verified"), "neutral pair shows four independent send and receive results");
        check(FaultLocalization.Overview(run).Title.Contains("passed") && FaultLocalization.Overview(run).Capture.Contains("have not run"), "quick-check success is limited to traffic and does not invent local inspections");
        run.Flows.Add(Flow("UDP", false, received: 0));
        check(TwoPcCheck.Build(run)[0].Result == "Delivery shortfall" && TwoPcCheck.Build(run)[1].Result == "Delivered", "one-way loss does not contaminate the reverse result");
        check(FaultLocalization.Overview(run).Title.Contains("receiver 192.0.2.20") && FaultLocalization.Overview(run).Detail.Contains("does not yet prove"), "one-way shortfall suggests receiver investigation without assigning blame");
        run.Flows.Add(Flow("UDP", true, received: 0));
        check(FaultLocalization.Overview(run).Title == "Delivery failed in both directions" && FaultLocalization.Overview(run).Detail.Contains("do not prove that both PCs"), "two failed directions can share one path fault");
        run.Flows.Add(Flow("UDP", false));
        check(TwoPcCheck.Build(run)[0].Result.Contains("earlier failure") && FaultLocalization.Overview(run).Title.Contains("both directions"), "passing retest preserves previous directional failures");
        run.Flows.Clear(); run.Flows.Add(Flow("UDP", false, 0, 0) with { SendError = "Socket bind failed" });
        check(TwoPcCheck.Build(run)[0].Result == "Send/connect incomplete" && FaultLocalization.Overview(run).Title.Contains("send/connect"), "send failure is distinguished from receiver shortfall");
        run.Flows.Clear(); run.Flows.Add(Flow("TCP", false) with { Outcome = Outcome.Failed, SendError = "Acknowledgement timed out" });
        check(TwoPcCheck.Build(run)[2].Result == "Delivered; completion error" && FaultLocalization.Overview(run).Title.Contains("Data arrived") &&
            !FaultLocalization.Overview(run).Traffic.Contains("delivery failed"), "verified delivery with an acknowledgement error does not blame the receiving PC");
        check(PacketPath.Build(run).Single().Finding!.Title.Contains("Data arrived"), "packet-path guidance agrees with verified delivery despite completion error");
        run.Flows.Clear(); run.Flows.Add(Flow("UDP", false) with { Outcome = Outcome.Inconclusive, Received = null, CoordinationIssue = "Receiver result unavailable" });
        check(TwoPcCheck.Build(run)[0].Send == "200/200 accepted" && TwoPcCheck.Build(run)[0].Receive == "Not measured" && TwoPcCheck.Build(run)[0].Result == "Test incomplete",
            "lost result exchange preserves accepted sends without fabricating zero received");
        check(PacketPath.Build(run).Single().Finding!.Title.Contains("exchange is incomplete"), "unknown result exchange cannot produce a packet-path drop verdict");
        run.Flows.Add(Flow("UDP", true) with { Sender = "192.0.2.99" });
        check(TwoPcCheck.Build(run)[1].Result == "Not tested", "unrelated address cannot create a directional pass");
        var saved = new PacketPathReport(Guid.NewGuid(), run.Started, [], FaultLocalization.Overview(run), TwoPcCheck.Build(run));
        check(Json.Read<PacketPathReport>(Json.Write(saved)).Directions!.SequenceEqual(saved.Directions!), "direction counts, errors and uncertainty survive reopening saved results");
        check(Json.Read<PacketPathReport>("{\"sessionId\":\"" + Guid.NewGuid() + "\",\"started\":\"2026-10-10T00:00:00Z\",\"flows\":[]}").Directions == null,
            "older saved packet-path reports remain readable without directional rows");
    }
}
