using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Elka.NetworkDiagnostics.Core;
using Elka.NetworkDiagnostics.Network;

internal static class CoordinatedCheckTests
{
    public static async Task Run(Action<bool, string> check)
    {
        static int Port() { var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); int port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop(); return port; }
        static async Task Wait(Func<bool> condition) { using var deadline = new CancellationTokenSource(10000); while (!condition()) await Task.Delay(20, deadline.Token); }
        async Task Reject(Func<Task> action, string name) { bool rejected = false; try { await action(); } catch { rejected = true; } check(rejected, name); }
        int ca = Port(), cb = Port(), testPort = Port();
        string code = Authenticator.NewCode();
        var oa = new PeerOptions("127.0.0.1", "127.0.0.2", code, "Endpoint", ca, cb, testPort, testPort);
        var ob = new PeerOptions("127.0.0.2", "127.0.0.1", code, "Endpoint", cb, ca, testPort, testPort);
        await using var sa = new SocketTests(oa); await using var sb = new SocketTests(ob);
        ConcurrentQueue<CheckSnapshot> seenA = new(), seenB = new(); bool busyB = false, legacyB = false;
        await using var coordinatorA = new CoordinatedCheck(oa, sa, s => { seenA.Enqueue(s); return Task.CompletedTask; });
        await using var coordinatorB = new CoordinatedCheck(ob, sb, s =>
        {
            if (busyB && !s.Initiator && s.Sequence == 0 && !s.Finished) throw new InvalidOperationException("Other PC busy");
            seenB.Enqueue(s); return Task.CompletedTask;
        });
        await using var a = new PeerService(oa, coordinatorA.Handle);
        await using var b = new PeerService(ob, (command, payload, ct) => legacyB && command == PeerCommand.Summary ? sb.Handle(command, payload, ct) : coordinatorB.Handle(command, payload, ct));
        coordinatorA.Peer = a; coordinatorB.Peer = b; a.Start(); b.Start();

        await coordinatorA.Run(default);
        var firstA = seenA.ToArray(); var firstB = seenB.ToArray();
        check(firstA.Length == 10 && firstB.Length == 10 && firstA[0].Id == firstB[0].Id && !firstB[0].Initiator && firstB[0].Sequence == 0,
            "one click starts a visible shared session on both endpoints before traffic");
        check(firstA[^1].Finished && firstB[^1].Finished && firstA[^1].Problem == "" && firstB[^1].Problem == "" &&
            firstA[^1].Flows.Count == 4 && firstA[^1].Flows.All(f => f.Outcome == Outcome.Passed && f.Received == 200) && firstA[^1].Flows.SequenceEqual(firstB[^1].Flows),
            "both PCs receive identical four-direction real UDP/TCP results and finish");
        check(firstB.Select(x => x.Sequence).SequenceEqual(new[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 8 }), "participant sees ordered live progress for every transfer");
        var local = new AdapterInfo("id", "Loopback", "Test", "127.0.0.2", "255.0.0.0", "", "Up", false);
        var assessment = new DiagnosticAssessment(local, "127.0.0.1", cb, testPort) { IsQuickCheck = true, IsFullScan = false };
        assessment.Flows.AddRange(firstB[^1].Flows);
        var rows = TwoPcCheck.Build(assessment);
        check(rows.Count == 4 && rows.All(x => x.Result == "Delivered") && rows[0].Sender == ob.Address, "shared results project from the participant's own PC perspective");

        seenA.Clear(); seenB.Clear(); await coordinatorB.Run(default);
        check(seenA.Last().Flows.SequenceEqual(seenB.Last().Flows) && seenA.Last().Flows.All(x => x.Outcome == Outcome.Passed) && !seenA.First().Initiator,
            "either PC can initiate the same shared check without role selection");

        seenA.Clear(); seenB.Clear(); busyB = true;
        await Reject(() => coordinatorA.Run(default), "busy participant rejects a new shared check"); busyB = false;
        check(seenA.IsEmpty && seenB.IsEmpty, "rejected start preserves both previous displayed results");
        legacyB = true;
        await Reject(() => coordinatorA.Run(default), "older peer without shared-check capability requires updating both PCs"); legacyB = false;
        check(seenA.IsEmpty && seenB.IsEmpty, "legacy peer is not falsely shown as having started a shared session");

        var reserved = new CheckStart(Guid.NewGuid());
        await a.Request(PeerCommand.BeginCheck, reserved); await a.Request(PeerCommand.BeginCheck, reserved);
        check(seenB.Count == 1, "repeated start with same shared ID is idempotent");
        await Reject(() => a.Request(PeerCommand.BeginCheck, new CheckStart(Guid.NewGuid())), "second session cannot overwrite an active participant");
        await Reject(() => coordinatorB.Run(default), "participant cannot initiate an overlapping session");
        await Reject(() => a.Request(PeerCommand.EndCheck, new CheckEnd(reserved.Id, true)), "no successful finish without all four observations");
        await Reject(() => a.Request(PeerCommand.UpdateCheck, new CheckUpdate(Guid.NewGuid(), 1)), "stale or unrelated session progress rejected");
        await a.Request(PeerCommand.UpdateCheck, new CheckUpdate(reserved.Id, 1));
        var foreign = firstA[^1].Flows[0] with { Receiver = "192.0.2.123" };
        await Reject(() => a.Request(PeerCommand.UpdateCheck, new CheckUpdate(reserved.Id, 2, foreign)), "out-of-scope shared flow rejected");
        await a.Request(PeerCommand.UpdateCheck, new CheckUpdate(reserved.Id, 2, firstA[^1].Flows[0]));
        await a.Request(PeerCommand.UpdateCheck, new CheckUpdate(reserved.Id, 2, firstA[^1].Flows[0]));
        check(seenB.Last().Flows.Count == 1, "repeated result does not double count the direction");
        await a.Request(PeerCommand.EndCheck, new CheckEnd(reserved.Id, false, "Interrupted test"));
        await a.Request(PeerCommand.EndCheck, new CheckEnd(reserved.Id, false, "Interrupted test"));
        await Reject(() => a.Request(PeerCommand.BeginCheck, reserved), "completed session cannot be resurrected by a delayed start");

        seenA.Clear(); seenB.Clear();
        using (var occupied = new UdpClient(new IPEndPoint(IPAddress.Parse(ob.Address), testPort))) await coordinatorA.Run(default);
        check(seenA.Last().Flows.SequenceEqual(seenB.Last().Flows) && seenB.Last().Flows[0] is { Outcome: Outcome.Inconclusive, Sent: null, Received: null } &&
            seenB.Last().Flows.Skip(1).All(f => f.Outcome == Outcome.Passed), "both PCs retain receiver preparation failure and still complete the other three directions");

        seenA.Clear(); seenB.Clear(); var cancelled = coordinatorA.Run(default);
        await Wait(() => seenB.Any(s => s.Sequence >= 3)); await coordinatorB.Cancel(); await cancelled;
        check(seenA.Last().Finished && seenB.Last().Finished && seenA.Last().Problem.Length > 0 && seenB.Last().Problem.Length > 0 &&
            seenB.Last().Flows.Count >= 1 && seenB.Last().Flows.Count < 4, "Cancel on participant stops the shared check and preserves partial results on both PCs");
        await Task.Delay(1200); // Any in-flight bounded remote sender finishes before the next test.
        seenA.Clear(); seenB.Clear(); using var cancelLocal = new CancellationTokenSource(); var localRun = coordinatorA.Run(cancelLocal.Token);
        await Wait(() => seenA.Any(s => s.Sequence >= 3)); cancelLocal.Cancel(); await localRun;
        check(seenB.Last().Finished && seenB.Last().Problem.Contains("Cancelled"), "Cancel on initiator finishes the participant instead of leaving it busy");
        await Task.Delay(1200);

        seenA.Clear(); seenB.Clear(); using var cancelFirst = new CancellationTokenSource(); var firstRun = coordinatorA.Run(cancelFirst.Token);
        await Wait(() => seenB.Any(s => s.Sequence == 1)); await Task.Delay(150); cancelFirst.Cancel(); await firstRun;
        check(seenB.Last().Finished && seenB.Last().Flows.Count == 0, "cancel during first transfer leaves unmeasured directions without a fabricated failure");
        var retryReceiver = await sb.Prepare(new("UDP", 1)); await sb.Finish(retryReceiver.Id);
        check(true, "cancelled initiating transfer releases the remote receive port immediately for retry");

        seenA.Clear(); seenB.Clear(); b.AcceptUdp = false; await a.Probe();
        await coordinatorA.Run(default); b.AcceptUdp = true;
        check(seenA.Last().Flows.All(f => f.Outcome == Outcome.Passed) && seenA.Last().Flows.SequenceEqual(seenB.Last().Flows),
            "shared check starts, updates and finishes over TCP when UDP control is unavailable");

        ConcurrentQueue<CheckSnapshot> abandoned = new();
        await using var lease = new CoordinatedCheck(ob, sb, s => { abandoned.Enqueue(s); return Task.CompletedTask; }, TimeSpan.FromMilliseconds(80));
        var lost = new CheckStart(Guid.NewGuid()); await lease.Handle(PeerCommand.BeginCheck, Json.Write(lost), default);
        await lease.Handle(PeerCommand.UpdateCheck, Json.Write(new CheckUpdate(lost.Id, 1)), default);
        await lease.Handle(PeerCommand.UpdateCheck, Json.Write(new CheckUpdate(lost.Id, 2, firstA[^1].Flows[0])), default);
        await Wait(() => abandoned.Any(s => s.Finished));
        check(abandoned.Last().Flows.Count == 1 && abandoned.Last().Problem.Contains("stopped reporting"), "participant timeout releases busy state and keeps completed direction after a lost connection");
        await lease.Handle(PeerCommand.BeginCheck, Json.Write(new CheckStart(Guid.NewGuid())), default);
        check(!abandoned.Last().Finished, "participant can accept a fresh check after timeout");
    }
}
