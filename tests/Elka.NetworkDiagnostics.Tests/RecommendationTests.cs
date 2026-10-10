using System.Net;
using System.Net.Sockets;
using Elka.NetworkDiagnostics.Core;
using Elka.NetworkDiagnostics.Windows;

internal static class RecommendationTests
{
    public static async Task Run(Action<bool, string> check, Func<Func<Task>, string, Task> throws)
    {
        List<int> visited = []; List<int> errors = [];
        await DiagnosticWorkflow.Run((n, _) => { visited.Add(n); return Task.CompletedTask; }, (n, _) => errors.Add(n),
            complete => { check(complete, "full scan reaches its final stage"); visited.Add(8); return Task.CompletedTask; }, default);
        check(visited.SequenceEqual(Enumerable.Range(1, 8)) && errors.Count == 0, "full workflow includes packet tracing and recommendations in order");
        visited.Clear();
        await DiagnosticWorkflow.Run((n, _) => { visited.Add(n); if (n == 6) throw new IOException("Denied filtering read"); return Task.CompletedTask; },
            (n, _) => errors.Add(n), _ => { visited.Add(8); return Task.CompletedTask; }, default);
        check(visited.SequenceEqual(Enumerable.Range(1, 8)) && errors.SequenceEqual([6]), "filtering failure does not skip tracing or recommendations");
        using var cancel = new CancellationTokenSource(); visited.Clear(); bool partial = false;
        await throws(() => DiagnosticWorkflow.Run((n, _) => { visited.Add(n); if (n == 3) cancel.Cancel(); return Task.CompletedTask; }, (_, _) => { },
            complete => { partial = !complete; return Task.CompletedTask; }, cancel.Token), "scan cancellation propagated");
        check(partial && visited.SequenceEqual([1, 2, 3]), "cancelled scan produces a partial assessment without starting more stages");

        var adapter = new AdapterInfo(Guid.NewGuid().ToString(), "LAN", "Test adapter", "192.0.2.10", "255.255.255.0", "192.0.2.1", "Up", false);
        DiagnosticAssessment Fresh() => new(adapter, "192.0.2.20", 47830, 47831);
        FlowObservation Flow(string protocol, bool reverse, Outcome outcome) => new(protocol, reverse ? "192.0.2.20" : adapter.Address, reverse ? adapter.Address : "192.0.2.20", 47831, outcome, outcome.ToString(),
            Expected: 200, Sent: 200, Received: outcome == Outcome.Passed ? 200 : outcome == Outcome.Failed ? 197 : null);
        bool Has(DiagnosticAssessment run, string title) => Recommendations.Analyze(run).Any(r => r.Title.Contains(title, StringComparison.Ordinal));
        var run = Fresh();
        check(Has(run, "missing two-PC") && Has(run, "missing packet evidence"), "missing tests and captures remain explicit");
        foreach (string protocol in new[] { "UDP", "TCP" }) foreach (bool reverse in new[] { false, true }) run.Flows.Add(Flow(protocol, reverse, Outcome.Passed));
        check(Has(run, "No network reset"), "four successful directional flows produce scoped no-reset guidance");
        run.Flows.RemoveAt(0);
        check(!Has(run, "No network reset"), "one missing direction cannot produce an all-protocol pass");
        run.Flows.Add(Flow("UDP", false, Outcome.Failed));
        check(Has(run, "failed direction") && !Has(run, "QoS"), "UDP failure points to its receiver without premature QoS advice");
        run.WfpCaptured = run.PacketsCaptured = true;
        check(!Has(run, "QoS"), "unreadable WFP data cannot justify the optional trial");
        run.WfpAnalyzed = true;
        check(!Has(run, "QoS"), "missing port ownership evidence prevents premature trial advice");
        run.PortsInspected = true;
        check(!Has(run, "QoS") && Has(run, "incomplete packet analysis"), "collected but unanalyzed capture cannot justify a QoS trial");
        run.PacketAnalysisComplete = true;
        check(Recommendations.Analyze(run).Single(r => r.AdminAction != null).AdminAction == "QosTrial", "UDP-only measured failure with collected evidence permits an explicitly optional trial");
        run.PacketAnalysisComplete = false;
        run.PacketAnalysisStatus = "Partial analysis: text limit reached.";
        check(!Has(run, "QoS") && Recommendations.Report(run, Recommendations.Analyze(run)).Contains(run.PacketAnalysisStatus), "partial analysis reaches final recommendations and blocks repair-trial advice");
        run.PacketAnalysisComplete = true;
        run.Flows.Add(Flow("UDP", false, Outcome.Passed));
        check(Has(run, "intermittent") && !Has(run, "No network reset"), "passing retest does not erase a measured failure");
        run.Flows.Add(Flow("TCP", false, Outcome.Inconclusive));
        check(!Has(run, "QoS"), "inconclusive TCP retest prevents TCP-healthy inference");
        run.Flows.RemoveAt(run.Flows.Count - 1);
        run.Drops.Add(new("UDP", "192.0.2.10", "192.0.2.20", 55000, 47831, "123"));
        check(Has(run, "filter that blocked") && !Has(run, "QoS"), "matching WFP drop prioritizes filter review over QoS trial");
        run.Drops.Clear();
        run.Ports.Add(new("UDP", "0.0.0.0", 47831, Environment.ProcessId + 1, "Other app"));
        check(Has(run, "other programs") && !Has(run, "QoS"), "other listener gets port guidance before a network change");
        run.Ports.Clear(); run.Ports.Add(new("UDP", "0.0.0.0", 47830, Environment.ProcessId, "Elka"));
        check(!Has(run, "other programs"), "own endpoint listener is not mistaken for a conflict");
        run.Ports.Add(new("UDP", "192.0.2.99", 47831, 1, "Different interface"));
        check(!Has(run, "other programs"), "unrelated interface listener excluded from conflict advice");
        run.Incomplete.Add("Packet tracing: UAC was declined");
        check(Has(run, "could not finish"), "declined or failed stages appear in final assessment");
        check(!Has(run, "QoS"), "incomplete evidence prevents optional repair-trial advice");
        var success = Fresh();
        foreach (string protocol in new[] { "UDP", "TCP" }) foreach (bool reverse in new[] { false, true }) success.Flows.Add(Flow(protocol, reverse, Outcome.Passed));
        success.WfpCaptured = success.WfpAnalyzed = success.PacketsCaptured = true;
        success.PacketAnalysisStatus = "Partial analysis: detail limit reached.";
        check(Has(success, "No network reset") && Has(success, "incomplete packet analysis") &&
            FaultLocalization.Overview(success).Capture.Contains("analysis incomplete") && FaultLocalization.Overview(success).Title.Contains("Test traffic passed"),
            "successful socket delivery and partial tracing remain distinct in overview and recommendations");
        var unrelated = Fresh(); unrelated.Flows.Add(Flow("UDP", false, Outcome.Failed) with { Port = 6980 });
        check(!Has(unrelated, "failed direction"), "a different test port cannot contaminate recommendations");
        var down = new DiagnosticAssessment(adapter with { Status = "Down" }, "192.0.2.20", 47830, 47831);
        check(Has(down, "physical connection"), "link-down result prioritizes physical checks");
        var apipa = new DiagnosticAssessment(adapter with { Address = "169.254.1.2" }, "192.0.2.20", 47830, 47831);
        check(Has(apipa, "address assignment"), "link-local versus routed peer produces address-assignment guidance");

        string Event(string source = "192.0.2.10", string destination = "192.0.2.20", string port = "47831", string protocol = "17", DateTimeOffset? when = null) =>
            $"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>5152</EventID><TimeCreated SystemTime='{(when ?? DateTimeOffset.UtcNow):O}'/></System><EventData><Data Name='SourceAddress'>{source}</Data><Data Name='DestAddress'>{destination}</Data><Data Name='SourcePort'>55000</Data><Data Name='DestPort'>{port}</Data><Data Name='Protocol'>{protocol}</Data><Data Name='FilterRTID'>123</Data></EventData></Event>";
        DateTimeOffset start = DateTimeOffset.UtcNow.AddMinutes(-1);
        List<PacketDrop> Parse(string xml) => PacketEvidence.MatchingDrops(xml, adapter.Address, "192.0.2.20", 47831, start);
        check(Parse(Event()).Single().FilterId == "123", "WFP XML matches selected flow and preserves filter identity");
        check(Parse(Event("192.0.2.20", adapter.Address, protocol: "6")).Single().Protocol == "TCP", "reverse TCP drop recognized independently");
        check(Parse(Event("::ffff:192.0.2.10")).Count == 1, "IPv4-mapped WFP address normalized");
        check(Parse(Event(destination: "192.0.2.99") + Event(port: "80") + Event(protocol: "1") + Event(when: start.AddSeconds(-1))).Count == 0,
            "unrelated address, port, protocol and stale WFP events excluded");
        check(Parse("No 5152 event was returned during this capture. This does not rule out filtering.").Count == 0, "empty WFP capture is not a fabricated drop");
        await throws(() => Task.FromResult(Parse("<Event>")), "truncated WFP XML rejected instead of a clean result");
        await throws(() => Task.FromResult(Parse("")), "missing WFP output cannot masquerade as a clean capture");
        await throws(() => Task.FromResult(Parse("<!DOCTYPE x [<!ENTITY a SYSTEM 'file:///C:/Windows/win.ini'>]><Event>&a;</Event>")), "external-entity WFP payload rejected");

        // Read-only host validation of the new structured port collector against owned sockets.
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var tcp = new TcpListener(IPAddress.Loopback, 0); tcp.Start();
        try
        {
            int udpPort = ((IPEndPoint)udp.Client.LocalEndPoint!).Port, tcpPort = ((IPEndPoint)tcp.LocalEndpoint).Port;
            var uses = await new WindowsDiagnostics().InspectPortUse(udpPort, tcpPort, default);
            check(uses.Any(p => p.Protocol == "UDP" && p.Port == udpPort && p.ProcessId == Environment.ProcessId), "Windows structured collector identifies real UDP owner");
            check(uses.Any(p => p.Protocol == "TCP" && p.Port == tcpPort && p.ProcessId == Environment.ProcessId), "Windows structured collector identifies real TCP listener");
        }
        finally { tcp.Stop(); }
    }
}
