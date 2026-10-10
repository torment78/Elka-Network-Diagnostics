using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Elka.NetworkDiagnostics.Core;

namespace Elka.NetworkDiagnostics.Network;

public record TestRequest(string Protocol, int Count = 200, int Size = 256, int IntervalMs = 5);
public record TestSpec(Guid Id, string Token, string Protocol, int Port, int Count, int Size, int IntervalMs);
public record SendResult(int Sent, int Echoes, double DurationMs, double? AverageRoundTripMs, string Error = "", double? AcknowledgedTransferMs = null);
public record ReceiveResult(Guid Id, string Protocol, int Expected, int Received, int Duplicates, int OutOfOrder, long Bytes, double DurationMs, double? ArrivalJitterMs, string Error, string ReceiverAddress, int Port);
public record TestResult(string Sender, string Receiver, TestSpec Spec, SendResult Send, ReceiveResult Receive)
{
    public bool Passed => Send.Error == "" && Receive.Error == "" && Send.Sent == Spec.Count && Receive.Received == Spec.Count;
    public FlowObservation Observation => new(Spec.Protocol, Sender, Receiver, Spec.Port, Passed ? Outcome.Passed : Outcome.Failed,
        Summary, Spec.Id, Spec.Count, Send.Sent, Receive.Received, Spec.Size, Send.Error, Receive.Error);
    public string Summary => $"{Spec.Protocol} {Sender} → {Receiver}: {Receive.Received}/{Send.Sent} {(Spec.Protocol == "UDP" ? "datagrams" : "test blocks")} received";
    public string Detail => $"Test {Spec.Id}\nTarget {Receiver}:{Spec.Port}; {Spec.Size} bytes/test block\nSent: {Send.Sent}; unique verified: {Receive.Received}; duplicates: {Receive.Duplicates}; out of order: {Receive.OutOfOrder}\n" +
        (Spec.Protocol == "UDP" ? $"Datagram loss: {(Send.Sent == 0 ? "unknown" : (100d * Math.Max(0, Send.Sent - Receive.Received) / Send.Sent).ToString("F1") + "%")}\nEchoes: {Send.Echoes}; average echo round trip: {Send.AverageRoundTripMs?.ToString("F2") ?? "unavailable"} ms\nArrival interval variation: {Receive.ArrivalJitterMs?.ToString("F2") ?? "unavailable"} ms\n" : $"Acknowledged whole transfer: {Send.AcknowledgedTransferMs?.ToString("F2") ?? "unavailable"} ms (not network RTT). TCP blocks are application records, not IP packet counts.\n") +
        $"Observed application transfer rate: {(Send.DurationMs > 0 ? Send.Sent * Spec.Size * 8d / Send.DurationMs / 1000 : 0):F2} Mbit/s (bounded test, not a bandwidth benchmark)\n{Send.Error} {Receive.Error}\nSocket delivery is measured. Sender/receiver NIC observation and VBAN processing were not measured by this test.";
}

public sealed class TestAttemptException(FlowObservation observation, Exception inner) : Exception(observation.CoordinationIssue, inner)
{
    public FlowObservation Observation { get; } = observation;
}

public sealed class SocketTests(PeerOptions options) : IAsyncDisposable
{
    private readonly ConcurrentDictionary<Guid, Receiver> receivers = new();
    private readonly SemaphoreSlim prepareLock = new(1);
    private readonly SemaphoreSlim sendLock = new(1);
    public event Action<Evidence>? Evidence;
    public async Task<string> Handle(PeerCommand command, string payload, CancellationToken ct) => command switch
    {
        PeerCommand.Summary => Json.Write(new PeerSummary(Environment.MachineName, options.Address, options.Role)),
        PeerCommand.PrepareTest => Json.Write(await Prepare(Json.Read<TestRequest>(payload))),
        PeerCommand.SendTest => Json.Write(await Send(Json.Read<TestSpec>(payload), ct)),
        PeerCommand.FinishTest => Json.Write(await Finish(Json.Read<Guid>(payload))),
        _ => throw new InvalidDataException("Unsupported diagnostic request.")
    };
    public async Task<TestSpec> Prepare(TestRequest request)
    {
        Validate(request);
        await prepareLock.WaitAsync();
        try
        {
            foreach (var old in receivers.Where(p => p.Value.Expired)) { if (receivers.TryRemove(old.Key, out var stale)) await stale.DisposeAsync(); }
            if (receivers.Count != 0) throw new InvalidOperationException("A receive test is already running.");
            var spec = new TestSpec(Guid.NewGuid(), Convert.ToHexString(RandomNumberGenerator.GetBytes(16)), request.Protocol, options.TestPort, request.Count, request.Size, request.IntervalMs);
            var receiver = new Receiver(options, spec);
            receivers[spec.Id] = receiver;
            return spec;
        }
        finally { prepareLock.Release(); }
    }
    public async Task<ReceiveResult> Finish(Guid id)
    {
        if (!receivers.TryRemove(id, out var receiver)) throw new InvalidOperationException("Test session expired or was not prepared.");
        await receiver.DisposeAsync(); var result = receiver.Snapshot();
        Evidence?.Invoke(Core.Evidence.Create("Protocol Testing", result.Error == "" && result.Received == result.Expected ? Outcome.Passed : Outcome.Failed,
            $"{result.Protocol} receive: {result.Received}/{result.Expected} at {options.Address}:{result.Port}", Json.Write(result), result.Id));
        return result;
    }
    public async Task<SendResult> Send(TestSpec spec, CancellationToken ct)
    {
        Validate(new(spec.Protocol, spec.Count, spec.Size, spec.IntervalMs));
        if (spec.Id == Guid.Empty || spec.Token.Length != 32 || !spec.Token.All(Uri.IsHexDigit) || spec.Port != options.PeerTestPort) throw new InvalidDataException("Invalid test token or unapproved destination port.");
        if (!await sendLock.WaitAsync(0, ct)) throw new InvalidOperationException("A send test is already running.");
        var elapsed = Stopwatch.StartNew(); int sent = 0; var rtts = new List<double>(); string error = "";
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(6000);
        try
        {
            if (spec.Protocol == "UDP")
            {
                using var sender = new UdpClient(new IPEndPoint(IPAddress.Parse(options.Address), 0));
                var target = new IPEndPoint(IPAddress.Parse(options.PeerAddress), spec.Port);
                using var echoLife = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
                var echoes = Task.Run(async () =>
                {
                    var seen = new HashSet<int>();
                    try
                    {
                        while (!echoLife.IsCancellationRequested)
                        {
                            var packet = await sender.ReceiveAsync(echoLife.Token);
                            if (!packet.RemoteEndPoint.Equals(target) || !ValidPacket(packet.Buffer, spec, out int sequence)) continue;
                            if (seen.Add(sequence)) rtts.Add(Stopwatch.GetElapsedTime(BinaryPrimitives.ReadInt64LittleEndian(packet.Buffer.AsSpan(40))).TotalMilliseconds);
                        }
                    }
                    catch (Exception e) when (e is OperationCanceledException or SocketException or ObjectDisposedException) { }
                }, CancellationToken.None);
                try
                {
                    for (int i = 0; i < spec.Count; i++)
                    {
                        await sender.SendAsync(Packet(spec, i), target, deadline.Token); sent++;
                        await Task.Delay(spec.IntervalMs, deadline.Token);
                    }
                    await Task.Delay(200, deadline.Token);
                }
                finally { echoLife.Cancel(); await echoes; }
            }
            else
            {
                using var sender = new TcpClient(new IPEndPoint(IPAddress.Parse(options.Address), 0));
                await sender.ConnectAsync(IPAddress.Parse(options.PeerAddress), spec.Port, deadline.Token);
                using var stream = sender.GetStream();
                for (int i = 0; i < spec.Count; i++) { await stream.WriteAsync(Packet(spec, i), deadline.Token); sent++; }
                sender.Client.Shutdown(SocketShutdown.Send);
                byte[] ack = new byte[1]; await stream.ReadExactlyAsync(ack, deadline.Token);
                if (ack[0] != 1) error = "Receiver did not verify the transfer.";
                else rtts.Add(elapsed.Elapsed.TotalMilliseconds);
            }
        }
        catch (Exception e) when (e is SocketException or IOException or OperationCanceledException) { error = ct.IsCancellationRequested ? "Test cancelled." : e is OperationCanceledException ? "Test timed out." : e.Message; }
        finally { sendLock.Release(); }
        var result = new SendResult(sent, spec.Protocol == "UDP" ? rtts.Count : 0, elapsed.Elapsed.TotalMilliseconds,
            spec.Protocol == "UDP" && rtts.Count > 0 ? rtts.Average() : null, error,
            spec.Protocol == "TCP" && rtts.Count > 0 ? rtts[0] : null);
        Evidence?.Invoke(Core.Evidence.Create("Protocol Testing", error.Length == 0 ? Outcome.Information : Outcome.Failed, $"{spec.Protocol} send: {sent} to {options.PeerAddress}:{spec.Port}", "Local socket send accepted these packets; remote delivery requires the receiver's result.\n" + Json.Write(result), spec.Id));
        return result;
    }
    public async Task<TestResult> Run(PeerService peer, string protocol, bool reverse, CancellationToken ct)
    {
        TestSpec? spec = null; SendResult? send = null; bool receiverFinished = false;
        string phase = "receiver preparation";
        try
        {
            spec = reverse ? await Prepare(new(protocol)) : Json.Read<TestSpec>(await peer.Request(PeerCommand.PrepareTest, new TestRequest(protocol), ct));
            phase = "sending";
            send = reverse ? Json.Read<SendResult>(await peer.Request(PeerCommand.SendTest, spec, ct)) : await Send(spec, ct);
            phase = "collecting the receiver result";
            await Task.Delay(200, ct);
            var receive = reverse ? await Finish(spec.Id) : Json.Read<ReceiveResult>(await peer.Request(PeerCommand.FinishTest, spec.Id, ct));
            receiverFinished = true;
            return new(reverse ? options.PeerAddress : options.Address, reverse ? options.Address : options.PeerAddress, spec, send, receive);
        }
        catch (Exception error) when (!ct.IsCancellationRequested && error is not OperationCanceledException)
        {
            string receiver = reverse ? options.Address : options.PeerAddress;
            string issue = phase == "receiver preparation" && (reverse || error is PeerOperationException)
                ? $"Receiver on {receiver} could not prepare the test: {error.Message}"
                : $"The test could not finish during {phase}: {error.Message}";
            throw new TestAttemptException(new(protocol, reverse ? options.PeerAddress : options.Address, receiver,
                spec?.Port ?? (reverse ? options.TestPort : options.PeerTestPort), Outcome.Inconclusive, issue,
                spec?.Id, spec?.Count, send?.Sent, null, spec?.Size, send?.Error ?? "", "", issue), error);
        }
        finally
        {
            if (spec != null && reverse && receivers.ContainsKey(spec.Id)) await Finish(spec.Id);
            if (spec != null && !reverse && !receiverFinished)
            {
                // Cancellation must release the other PC's listener too, so a fresh check
                // does not report our abandoned receiver as an occupied port.
                try { using var cleanup = new CancellationTokenSource(2500); await peer.Request(PeerCommand.FinishTest, spec.Id, cleanup.Token); }
                catch { /* A disconnected remote receiver also closes itself after 10 seconds. */ }
            }
        }
    }
    public static void Validate(TestRequest r)
    {
        if (r.Protocol is not ("TCP" or "UDP") || r.Count is < 1 or > 300 || r.Size is < 64 or > 1200 || r.IntervalMs is < 1 or > 10) throw new ArgumentException("Test exceeds the bounded diagnostic limits.");
    }
    public static byte[] Packet(TestSpec spec, int sequence)
    {
        byte[] bytes = new byte[spec.Size]; "ELK1"u8.CopyTo(bytes); spec.Id.TryWriteBytes(bytes.AsSpan(4)); Convert.FromHexString(spec.Token).CopyTo(bytes, 20);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(36), sequence); BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(40), Stopwatch.GetTimestamp());
        for (int i = 48; i < bytes.Length; i++) bytes[i] = (byte)(i + sequence);
        return bytes;
    }
    public static bool ValidPacket(byte[] bytes, TestSpec spec, out int sequence)
    {
        sequence = -1;
        if (bytes.Length != spec.Size || !bytes.AsSpan(0, 4).SequenceEqual("ELK1"u8) || new Guid(bytes.AsSpan(4, 16)) != spec.Id || !CryptographicOperations.FixedTimeEquals(bytes.AsSpan(20, 16), Convert.FromHexString(spec.Token))) return false;
        sequence = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(36));
        if (sequence < 0 || sequence >= spec.Count) return false;
        for (int i = 48; i < bytes.Length; i++) if (bytes[i] != (byte)(i + sequence)) return false;
        return true;
    }
    public async ValueTask DisposeAsync() { foreach (var r in receivers.Values) await r.DisposeAsync(); receivers.Clear(); }

    private sealed class Receiver : IAsyncDisposable
    {
        private readonly PeerOptions options; private readonly TestSpec spec;
        private readonly CancellationTokenSource deadline = new(10_000);
        private readonly Stopwatch timer = Stopwatch.StartNew(); private readonly HashSet<int> seen = [];
        private readonly List<double> intervals = []; private double? lastArrival; private int duplicates, outOfOrder, high = -1; private long bytes; private string error = "";
        private readonly UdpClient? udp; private readonly TcpListener? tcp; private readonly Task loop;
        public bool Expired => timer.Elapsed.TotalSeconds > 15;
        public Receiver(PeerOptions options, TestSpec spec)
        {
            this.options = options; this.spec = spec;
            try
            {
                if (spec.Protocol == "UDP") { udp = new UdpClient(AddressFamily.InterNetwork); udp.ExclusiveAddressUse = true; udp.Client.Bind(new IPEndPoint(IPAddress.Parse(options.Address), spec.Port)); }
                else { tcp = new TcpListener(IPAddress.Parse(options.Address), spec.Port); tcp.Server.ExclusiveAddressUse = true; tcp.Start(4); }
                loop = Receive();
            }
            catch { udp?.Dispose(); tcp?.Stop(); deadline.Dispose(); throw; }
        }
        private async Task Receive()
        {
            try
            {
                if (udp != null)
                {
                    while (!deadline.IsCancellationRequested)
                    {
                        var packet = await udp.ReceiveAsync(deadline.Token);
                        if (packet.RemoteEndPoint.Address.ToString() != options.PeerAddress || !ValidPacket(packet.Buffer, spec, out int sequence)) continue;
                        Add(sequence, packet.Buffer.Length);
                        await udp.SendAsync(packet.Buffer, packet.RemoteEndPoint, deadline.Token);
                    }
                }
                else
                {
                    while (!deadline.IsCancellationRequested)
                    {
                        using var client = await tcp!.AcceptTcpClientAsync(deadline.Token);
                        if (((IPEndPoint)client.Client.RemoteEndPoint!).Address.ToString() != options.PeerAddress) continue;
                        using var stream = client.GetStream();
                        for (int i = 0; i < spec.Count; i++)
                        {
                            byte[] packet = new byte[spec.Size]; await stream.ReadExactlyAsync(packet, deadline.Token);
                            if (!ValidPacket(packet, spec, out int sequence)) throw new InvalidDataException("TCP test payload verification failed.");
                            Add(sequence, packet.Length);
                        }
                        await stream.WriteAsync(new byte[] { 1 }, deadline.Token); break;
                    }
                }
            }
            catch (Exception e) when (e is OperationCanceledException or ObjectDisposedException) { }
            catch (Exception e) when (e is SocketException or IOException) { if (!deadline.IsCancellationRequested) error = e.Message; }
            finally { udp?.Dispose(); tcp?.Stop(); }
        }
        private void Add(int sequence, int length)
        {
            if (!seen.Add(sequence)) { duplicates++; return; }
            if (sequence < high) outOfOrder++; high = Math.Max(high, sequence); bytes += length;
            double now = timer.Elapsed.TotalMilliseconds; if (lastArrival is double last) intervals.Add(now - last); lastArrival = now;
        }
        public ReceiveResult Snapshot() => new(spec.Id, spec.Protocol, spec.Count, seen.Count, duplicates, outOfOrder, bytes, timer.Elapsed.TotalMilliseconds,
            intervals.Count < 2 ? null : intervals.Zip(intervals.Skip(1), (a, b) => Math.Abs(a - b)).Average(), error, options.Address, spec.Port);
        public async ValueTask DisposeAsync() { deadline.Cancel(); udp?.Dispose(); tcp?.Stop(); await loop; }
    }
}
