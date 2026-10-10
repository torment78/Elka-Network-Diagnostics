using Elka.NetworkDiagnostics.Core;
using Elka.NetworkDiagnostics.Windows;

internal static class LocalizationTests
{
    public static void Run(Action<bool, string> check)
    {
        var now = DateTimeOffset.UtcNow;
        string State(DateTimeOffset time, string name = "Example block", string action = "FWP_ACTION_BLOCK", string id = "42") => $"""
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <wfpstate><timeStamp>{time:O}</timeStamp><providers><item><providerKey>provider</providerKey><displayData><name>Example security provider</name></displayData><serviceName>ExampleService</serviceName></item></providers>
            <layers><item><layer><layerKey>FWPM_LAYER_INBOUND_TRANSPORT_V4</layerKey><layerId>12</layerId><displayData><name>Inbound transport v4</name></displayData></layer>
            <callouts/><filters><item><filterId>{id}</filterId><filterKey>key</filterKey><displayData><name>{name}</name></displayData><providerKey>provider</providerKey><layerKey>FWPM_LAYER_INBOUND_TRANSPORT_V4</layerKey><action><type>{action}</type></action></item></filters></item></layers></wfpstate><firewallState/>
            """;
        var before = WfpState.Read(State(now.AddSeconds(-30)));
        var after = WfpState.Read(State(now.AddSeconds(1)));
        var drop = new PacketDrop("UDP", "192.0.2.10", "192.0.2.20", 50000, 47831, "42", now, "Rule-1", "12", "4");
        var enriched = WfpState.Corroborate(drop, before, after);
        check(enriched.Context is { Name: "Example block", Provider: "Example security provider", Service: "ExampleService", Layer: "Inbound transport v4" }, "actual netsh multi-root shape maps filters, layers and providers");
        check(WfpState.Corroborate(drop, before, null).Context == null && WfpState.Corroborate(drop with { Time = null }, before, after).Context == null, "missing bracketing state or event time cannot identify runtime filter ownership");
        check(WfpState.Corroborate(drop with { Time = now.AddMinutes(-1) }, before, after).Context == null, "old event cannot borrow current runtime filter identity");
        check(WfpState.Corroborate(drop, before, WfpState.Read(State(now.AddMinutes(6)))).Context == null, "distant state snapshots cannot corroborate filter identity");
        check(WfpState.Corroborate(drop with { LayerId = "99" }, before, after).Context == null, "mismatched WFP layer prevents attribution");
        check(WfpState.Corroborate(drop, before, WfpState.Read(State(now.AddSeconds(1), action: "FWP_ACTION_PERMIT"))).Context == null, "changed filter configuration is rejected despite matching name and ID");
        check(WfpState.Corroborate(drop, before, WfpState.Read(State(now.AddSeconds(1), name: "Replacement"))).Context == null, "reused runtime ID with a different filter is rejected");
        bool Reject(string xml) { try { WfpState.Read(xml); return false; } catch { return true; } }
        check(Reject("<!DOCTYPE capture [<!ENTITY x SYSTEM 'file:///secret'>]>" + State(now)), "WFP parser rejects external-entity declarations");
        check(Reject("<wfpstate/><firewallState/>"), "untimestamped state remains unknown");
        string eventXml = $"""
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>5152</EventID><TimeCreated SystemTime="{now:O}"/></System><EventData>
            <Data Name="Protocol">17</Data><Data Name="SourceAddress">192.0.2.10</Data><Data Name="DestAddress">192.0.2.20</Data><Data Name="SourcePort">50000</Data><Data Name="DestPort">47831</Data><Data Name="FilterRTID">42</Data><Data Name="FilterOrigin">Rule-1</Data><Data Name="LayerRTID">12</Data><Data Name="InterfaceIndex">4</Data></EventData></Event>
            """;
        var parsed = PacketEvidence.MatchingDrops(eventXml, "192.0.2.20", "192.0.2.10", 47831, now.AddMinutes(-1)).Single();
        check(parsed.FilterOrigin == "Rule-1" && parsed.LayerId == "12" && parsed.InterfaceIndex == "4" && parsed.Time == now, "Windows event origin, interface, layer and timestamp retained directly");
        check(FaultLocalization.Describe(enriched).Contains("corroborate") && FaultLocalization.Describe(enriched).Contains("not an individual"), "ownership explanation preserves runtime-ID and flow-correlation limits");

        var run = new DiagnosticAssessment(new("id", "Ethernet", "NIC", "192.0.2.20", "255.255.255.0", "", "Up", false), "192.0.2.10", 47830, 47831);
        var flow = new FlowObservation("UDP", run.Peer, run.Adapter.Address, 47831, Outcome.Failed, "197/200", Guid.NewGuid(), 200, 200, 197, 256);
        run.Flows.Add(flow);
        var focus = FaultLocalization.Overview(run);
        check(focus.Title.Contains("receiver 192.0.2.20") && focus.Detail.Contains("does not yet prove"), "failed direction focuses receiver without falsely identifying a blocked PC");
        run.PacketSnapshots.Add(new(flow.TestId!.Value, 2, 7, 1, "99", 1, "Rx", "INET: transport endpoint was not found"));
        var finding = FaultLocalization.ForFlow(run, flow);
        check(finding.NextStage == 4 && finding.Title.Contains("receiving socket"), "specific transport drop directs user to socket readiness and port inspection");
        check(FaultLocalization.Overview(run).Title.Contains("has a recorded drop"), "matching local drop evidence focuses the local PC");
        run.Drops.Add(enriched);
        check(FaultLocalization.ForFlow(run, flow).NextStage == 6 && FaultLocalization.ForFlow(run, flow).Evidence.Contains("Rule-1"), "WFP evidence selects filtering stage and preserves direct event origin");
        run.Drops.Clear(); run.PacketSnapshots.Clear();
        check(FaultLocalization.ForFlow(run, flow).NextStage == 7 && FaultLocalization.ForFlow(run, flow).Title.Contains("not yet"), "missing snapshots trigger capture work instead of invented blame");
        run.Flows.Clear();
        foreach (string protocol in new[] { "UDP", "TCP" })
            foreach (bool reverse in new[] { false, true })
                run.Flows.Add(flow with { Protocol = protocol, Sender = reverse ? run.Peer : run.Adapter.Address, Receiver = reverse ? run.Adapter.Address : run.Peer, Outcome = Outcome.Passed, Received = 200, TestId = Guid.NewGuid() });
        focus = FaultLocalization.Overview(run);
        check(focus.Title.Contains("passed") && focus.Traffic.Contains("UDP: passed") && focus.Capture.Contains("incomplete"), "successful socket tests stay passed when packet capture is incomplete");
        run.Drops.Add(drop with { Sender = "192.0.2.99" });
        run.PacketSnapshots.Add(new(Guid.NewGuid(), 0, 1, 1, "1", 1, "Rx", "foreign"));
        check(!FaultLocalization.Overview(run).Title.Contains("recorded drop"), "unrelated flow and test drops cannot focus blame on this PC");
        run.Flows.Add(flow);
        check(FaultLocalization.Overview(run).Traffic.Contains("delivery failed"), "overview preserves a failure alongside successful retests");
        run.Flows.Clear(); run.Drops.Clear(); run.Drops.Add(enriched);
        var capturedOnly = PacketPath.Build(run).Single();
        check(capturedOnly.Finding?.HasLocalDrop == true && capturedOnly.Checkpoints[5].State == "Incomplete", "capture-only WFP rejection is visible without manufacturing a completed socket test");
    }
}
