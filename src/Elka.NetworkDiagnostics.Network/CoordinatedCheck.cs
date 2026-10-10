using System.Diagnostics;
using Elka.NetworkDiagnostics.Core;

namespace Elka.NetworkDiagnostics.Network;

public record CheckStart(Guid Id);
public record CheckUpdate(Guid Id, int Sequence, FlowObservation? Flow = null);
public record CheckEnd(Guid Id, bool Completed, string Reason = "");
public record CheckSnapshot(Guid Id, bool Initiator, int Sequence, IReadOnlyList<FlowObservation> Flows,
    bool Finished = false, string Problem = "")
{
    public string Status => Finished ? (Problem.Length == 0 ? "Two-PC check finished." : "Two-PC check incomplete: " + Problem)
        : Sequence == 0 ? "Two-PC check started on both PCs…"
        : $"Checking {(Sequence <= 4 ? "UDP" : "TCP")} · direction {Math.Min(4, (Sequence + 1) / 2)} of 4…";
}

// A single coordinator drives four transfers. The participant performs the actual socket work
// through the existing authenticated RPCs and receives the same combined observations.
// No elevated operation, capture or repair is exposed through these commands.
public sealed class CoordinatedCheck : IAsyncDisposable
{
    private readonly PeerOptions options;
    private readonly SocketTests tests;
    private readonly Func<CheckSnapshot, Task> changed;
    private readonly TimeSpan lease;
    private readonly SemaphoreSlim gate = new(1);
    private readonly CancellationTokenSource life = new();
    private readonly Queue<Guid> completed = new();
    private readonly Task watchdog;
    private State? active;
    public PeerService? Peer { get; set; }
    private sealed class State(Guid id, bool initiator)
    {
        public readonly Guid Id = id;
        public readonly bool Initiator = initiator;
        public readonly CancellationTokenSource Stop = new();
        public readonly List<FlowObservation> Flows = [];
        public int Sequence;
        public bool Published;
        public long Touched = Stopwatch.GetTimestamp();
        public CheckSnapshot Snapshot(bool finished = false, string problem = "") => new(Id, Initiator, Sequence, Flows.ToArray(), finished, problem);
    }

    public CoordinatedCheck(PeerOptions options, SocketTests tests, Func<CheckSnapshot, Task> changed, TimeSpan? participantTimeout = null)
    {
        this.options = options; this.tests = tests; this.changed = changed;
        lease = participantTimeout ?? TimeSpan.FromSeconds(90);
        watchdog = Watch();
    }

    public async Task<string> Handle(PeerCommand command, string payload, CancellationToken ct)
    {
        if (command == PeerCommand.Summary)
            return Json.Write(new PeerSummary(Environment.MachineName, options.Address, options.Role, SharedCheck: true));
        if (command is not (PeerCommand.BeginCheck or PeerCommand.UpdateCheck or PeerCommand.EndCheck or PeerCommand.CancelCheck))
            return await tests.Handle(command, payload, ct);
        await gate.WaitAsync(ct);
        try
        {
            life.Token.ThrowIfCancellationRequested();
            if (command == PeerCommand.BeginCheck)
            {
                var start = Json.Read<CheckStart>(payload);
                if (start.Id == Guid.Empty || completed.Contains(start.Id)) throw new InvalidDataException("This check has already ended or has an invalid ID.");
                if (active?.Id == start.Id && !active.Initiator) return "ready";
                if (active != null) throw new InvalidOperationException("The other PC is already checking. Wait for it to finish, then click Check both PCs on one PC only.");
                var state = new State(start.Id, false); active = state;
                try { await changed(state.Snapshot()); state.Published = true; }
                catch { active = null; state.Stop.Dispose(); throw; }
                return "ready";
            }
            if (command == PeerCommand.UpdateCheck)
            {
                var update = Json.Read<CheckUpdate>(payload);
                var state = Participant(update.Id);
                Validate(update);
                if (update.Sequence == state.Sequence && (update.Flow == null || state.Flows.LastOrDefault() == update.Flow)) return "received";
                if (update.Sequence != state.Sequence + 1) throw new InvalidDataException("Check progress arrived out of order.");
                state.Sequence = update.Sequence; state.Touched = Stopwatch.GetTimestamp();
                if (update.Flow != null) state.Flows.Add(update.Flow);
                await changed(state.Snapshot()); return "received";
            }
            if (command == PeerCommand.CancelCheck)
            {
                var cancel = Json.Read<CheckStart>(payload);
                if (completed.Contains(cancel.Id)) return "ended";
                if (active?.Id != cancel.Id) throw new InvalidDataException("No matching two-PC check is running.");
                active.Stop.Cancel();
                if (!active.Initiator) await EndLocal(active, "Cancelled from the other PC.");
                return "cancelled";
            }
            var end = Json.Read<CheckEnd>(payload);
            if (completed.Contains(end.Id)) return "ended";
            var participant = Participant(end.Id);
            if (end.Reason == null || end.Reason.Length > 1024 || (end.Completed && (participant.Sequence != 8 || participant.Flows.Count != 4)))
                throw new InvalidDataException("The check cannot complete without all four direction results.");
            await EndLocal(participant, end.Completed ? "" : (end.Reason.Length == 0 ? "The other PC stopped the check." : end.Reason));
            return "ended";
        }
        finally { gate.Release(); }
    }

    public async Task Run(CancellationToken ct)
    {
        var peer = Peer ?? throw new InvalidOperationException("Start both endpoints first.");
        var summary = Json.Read<PeerSummary>(await peer.Request(PeerCommand.Summary, new { }, ct));
        if (!summary.SharedCheck) throw new InvalidOperationException("Update the app on both PCs to version 0.2.1 or newer to start the check on both screens.");
        var state = new State(Guid.NewGuid(), true);
        await gate.WaitAsync(ct);
        try
        {
            if (active != null) throw new InvalidOperationException("A two-PC check is already running.");
            active = state;
        }
        finally { gate.Release(); }
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct, state.Stop.Token, life.Token);
        string problem = ""; bool requested = false;
        try
        {
            requested = true;
            await peer.Request(PeerCommand.BeginCheck, new CheckStart(state.Id), stop.Token);
            await gate.WaitAsync(stop.Token);
            try { await changed(state.Snapshot()); state.Published = true; }
            finally { gate.Release(); }
            for (int step = 0; step < 4; step++)
            {
                stop.Token.ThrowIfCancellationRequested();
                string protocol = step < 2 ? "UDP" : "TCP"; bool reverse = step % 2 == 1;
                await Publish(state, new(state.Id, step * 2 + 1), stop.Token);
                FlowObservation flow;
                try { var result = await tests.Run(peer, protocol, reverse, stop.Token); flow = result.Observation with { Detail = result.Summary + "\n" + result.Detail }; }
                catch (TestAttemptException e) { flow = e.Observation; }
                await Publish(state, new(state.Id, step * 2 + 2, flow), stop.Token);
            }
            await peer.Request(PeerCommand.EndCheck, new CheckEnd(state.Id, true), stop.Token);
        }
        catch (Exception e)
        {
            problem = e is OperationCanceledException ? "Cancelled; unfinished directions were not measured." : e.Message;
            if (problem.Length > 1024) problem = problem[..1024];
            if (requested)
            {
                try { using var deadline = new CancellationTokenSource(4000); await peer.Request(PeerCommand.EndCheck, new CheckEnd(state.Id, false, problem), deadline.Token); }
                catch { /* A disconnected participant retains partial results and releases its lease. */ }
            }
            if (!state.Published) throw;
        }
        finally
        {
            await gate.WaitAsync();
            try { if (active == state) await EndLocal(state, problem); }
            finally { gate.Release(); state.Stop.Dispose(); }
        }
    }

    private async Task Publish(State state, CheckUpdate update, CancellationToken ct)
    {
        await gate.WaitAsync(ct);
        try
        {
            state.Sequence = update.Sequence;
            if (update.Flow != null) state.Flows.Add(update.Flow);
            await changed(state.Snapshot());
        }
        finally { gate.Release(); }
        await Peer!.Request(PeerCommand.UpdateCheck, update, ct);
    }

    public async Task Cancel()
    {
        State? state;
        await gate.WaitAsync();
        try
        {
            state = active; if (state == null) return;
            state.Stop.Cancel();
            if (!state.Initiator) await EndLocal(state, "Cancelled on this PC; unfinished directions were not measured.");
        }
        finally { gate.Release(); }
        try { using var deadline = new CancellationTokenSource(4000); if (Peer != null) await Peer.Request(PeerCommand.CancelCheck, new CheckStart(state.Id), deadline.Token); }
        catch { /* The other PC also has a bounded operation or participant lease. */ }
    }

    private State Participant(Guid id) => active is { Initiator: false } state && state.Id == id ? state
        : throw new InvalidDataException("No matching check is waiting for results on this PC.");

    private void Validate(CheckUpdate update)
    {
        if (update.Sequence is < 1 or > 8 || (update.Sequence % 2 == 0) != (update.Flow != null)) throw new InvalidDataException("Invalid check progress.");
        if (update.Flow is not { } flow) return;
        bool toInitiator = update.Sequence is 4 or 8;
        string sender = toInitiator ? options.Address : options.PeerAddress;
        string receiver = toInitiator ? options.PeerAddress : options.Address;
        if (flow.Protocol != (update.Sequence <= 4 ? "UDP" : "TCP") || flow.Sender != sender || flow.Receiver != receiver ||
            flow.Port != (toInitiator ? options.PeerTestPort : options.TestPort) || !Enum.IsDefined(flow.Outcome) ||
            flow.Expected is < 0 or > 200 || flow.Sent is < 0 or > 200 || flow.Received is < 0 or > 200 ||
            flow.Detail == null || flow.Detail.Length > 12000 || flow.SendError == null || flow.SendError.Length > 4000 ||
            flow.ReceiveError == null || flow.ReceiveError.Length > 4000 || flow.CoordinationIssue == null || flow.CoordinationIssue.Length > 4000 ||
            (flow.Outcome == Outcome.Passed && (flow.Expected != 200 || flow.Sent != 200 || flow.Received != 200)))
            throw new InvalidDataException("The shared result does not match the selected test flow.");
    }

    // Caller holds gate. Notify before releasing the active session so UI events cannot overtake it.
    private async Task EndLocal(State state, string problem)
    {
        state.Stop.Cancel();
        try { if (state.Published) await changed(state.Snapshot(true, problem)); }
        finally
        {
            active = null; completed.Enqueue(state.Id); while (completed.Count > 32) completed.Dequeue();
            if (!state.Initiator) state.Stop.Dispose();
        }
    }
    private async Task Watch()
    {
        try
        {
            while (!life.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(1000, lease.TotalMilliseconds)), life.Token);
                await gate.WaitAsync(life.Token);
                try
                {
                    if (active is { Initiator: false } state && Stopwatch.GetElapsedTime(state.Touched) > lease)
                        await EndLocal(state, "The other PC stopped reporting progress. Completed directions were retained; remaining directions were not measured.");
                }
                finally { gate.Release(); }
            }
        }
        catch (OperationCanceledException) { }
    }
    public async ValueTask DisposeAsync()
    {
        life.Cancel(); await watchdog;
        await gate.WaitAsync();
        try { if (active is { } state) await EndLocal(state, "Endpoint closed before the check finished."); }
        finally { gate.Release(); }
    }
}
