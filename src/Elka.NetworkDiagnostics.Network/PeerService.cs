using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Elka.NetworkDiagnostics.Core;

namespace Elka.NetworkDiagnostics.Network;

public sealed class PeerService : IAsyncDisposable
{
    private readonly PeerOptions options;
    private readonly Authenticator auth;
    private readonly CancellationTokenSource life = new();
    private readonly ConcurrentDictionary<Guid, TaskCompletionSource<Envelope>> pending = new();
    private readonly ConcurrentDictionary<Guid, Cached> received = new();
    private readonly SemaphoreSlim incoming = new(16);
    private readonly Func<PeerCommand, string, CancellationToken, Task<string>> handler;
    private UdpClient? udp;
    private TcpListener? tcp;
    private Task[] loops = [];
    public TransportHealth Health { get; private set; } = new(false, false, "Offline", DateTimeOffset.UtcNow, "Not probed");
    public event Action<TransportHealth>? HealthChanged;
    public event Action<string>? Log;
    // Fault injection affects control transport only; used by the loopback integration harness.
    public bool AcceptUdp { get; set; } = true;
    public bool AcceptTcp { get; set; } = true;
    private record Cached(long Created, PeerCommand Command, string Payload, Lazy<Task<PeerReply>> Reply);

    public PeerService(PeerOptions options, Func<PeerCommand, string, CancellationToken, Task<string>> handler)
    {
        this.options = options; this.handler = handler; auth = new(options.PairingCode);
        ValidateAddress(options.Address); ValidateAddress(options.PeerAddress);
        ValidatePort(options.ControlPort); ValidatePort(options.PeerControlPort); ValidatePort(options.TestPort);
        if (options.ControlPort == options.TestPort) throw new ArgumentException("Control and test ports must be different.");
    }
    public static void ValidatePort(int port) { if (port is < 1024 or > 65535) throw new ArgumentException("Choose a port from 1024 to 65535."); }
    public static IPAddress ValidateAddress(string address)
    {
        if (!IPAddress.TryParse(address, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.Broadcast) || ip.GetAddressBytes()[0] >= 224) throw new ArgumentException("Enter a specific unicast IPv4 address.");
        return ip;
    }
    public void Start()
    {
        if (udp != null) throw new InvalidOperationException("Endpoint already started.");
        var address = IPAddress.Parse(options.Address);
        try
        {
            udp = new UdpClient(AddressFamily.InterNetwork); udp.ExclusiveAddressUse = true; udp.Client.Bind(new IPEndPoint(address, options.ControlPort));
            tcp = new TcpListener(address, options.ControlPort); tcp.Server.ExclusiveAddressUse = true; tcp.Start(16);
            loops = [UdpLoop(), TcpLoop(), HealthLoop()];
        }
        catch { udp?.Dispose(); tcp?.Stop(); udp = null; throw; }
    }
    public async Task<string> Request(PeerCommand command, object payload, CancellationToken ct = default)
    {
        if (udp == null) throw new InvalidOperationException("Start the endpoint first.");
        var e = auth.Create(Guid.NewGuid(), false, command, Json.Write(payload));
        Exception? last = null;
        string[] order = Health.Udp || !Health.Tcp ? ["UDP", "TCP"] : ["TCP", "UDP"];
        foreach (string transport in order)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var reply = transport == "UDP" ? await OverUdp(e, ct) : await OverTcp(e, ct);
                if (!reply.Ok) throw new PeerOperationException(reply.Error);
                if (transport != Health.Active) Log?.Invoke($"Control request delivered over {transport}.");
                return reply.Payload;
            }
            catch (PeerOperationException) { throw; }
            catch (Exception ex) when (ex is SocketException or IOException or TimeoutException or OperationCanceledException)
            { if (ct.IsCancellationRequested) throw; last = ex; }
        }
        throw new IOException("Neither control transport responded. Check peer address, pairing code, both clocks, and firewall access. Local diagnostics remain available.", last);
    }
    public async Task<TransportHealth> Probe(CancellationToken ct = default)
    {
        async Task<bool> Check(bool isUdp)
        {
            try
            {
                var frame = auth.Create(Guid.NewGuid(), false, PeerCommand.Ping, "{}");
                return (isUdp ? await OverUdp(frame, ct) : await OverTcp(frame, ct)).Ok;
            }
            catch (Exception e) when (e is SocketException or IOException or TimeoutException or OperationCanceledException) { return false; }
        }
        Task<bool> u = Check(true), t = Check(false); await Task.WhenAll(u, t);
        Health = new(u.Result, t.Result, u.Result ? "UDP" : t.Result ? "TCP" : "Offline", DateTimeOffset.UtcNow, "Authenticated round trip on the selected control address and port only.");
        HealthChanged?.Invoke(Health); return Health;
    }
    private async Task<PeerReply> OverUdp(Envelope frame, CancellationToken ct)
    {
        var completion = new TaskCompletionSource<Envelope>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!pending.TryAdd(frame.Id, completion)) throw new InvalidOperationException("Duplicate active request.");
        try
        {
            byte[] data = Encoding.UTF8.GetBytes(Json.Write(frame));
            var end = new IPEndPoint(IPAddress.Parse(options.PeerAddress), options.PeerControlPort);
            for (int attempt = 0; attempt < 3; attempt++)
            {
                await udp!.SendAsync(data, end, ct);
                try
                {
                    var reply = await completion.Task.WaitAsync(TimeSpan.FromMilliseconds(750), ct);
                    if (reply.Command != frame.Command) throw new InvalidDataException("Response command mismatch.");
                    return Json.Read<PeerReply>(reply.Payload);
                }
                catch (TimeoutException) when (attempt < 2) { }
            }
            throw new TimeoutException("UDP control timed out.");
        }
        finally { pending.TryRemove(frame.Id, out _); }
    }
    private async Task<PeerReply> OverTcp(Envelope frame, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct, life.Token); timeout.CancelAfter(TimeSpan.FromSeconds(8));
        using var client = new TcpClient(new IPEndPoint(IPAddress.Parse(options.Address), 0));
        await client.ConnectAsync(IPAddress.Parse(options.PeerAddress), options.PeerControlPort, timeout.Token);
        using var stream = client.GetStream();
        await Authenticator.WriteAsync(stream, frame, timeout.Token);
        var reply = await Authenticator.ReadAsync(stream, timeout.Token);
        if (!auth.Verify(reply) || !reply.Response || reply.Id != frame.Id || reply.Command != frame.Command) throw new InvalidDataException("Unauthenticated or mismatched response.");
        return Json.Read<PeerReply>(reply.Payload);
    }
    private async Task UdpLoop()
    {
        while (!life.IsCancellationRequested)
        {
            try
            {
                var packet = await udp!.ReceiveAsync(life.Token);
                if (!AcceptUdp || packet.Buffer.Length > Authenticator.MaxFrame || packet.RemoteEndPoint.Address.ToString() != options.PeerAddress || packet.RemoteEndPoint.Port != options.PeerControlPort) continue;
                var frame = Json.Read<Envelope>(Encoding.UTF8.GetString(packet.Buffer));
                if (!auth.Verify(frame)) continue;
                if (frame.Response) { if (pending.TryGetValue(frame.Id, out var waiter)) waiter.TrySetResult(frame); }
                else if (incoming.Wait(0)) _ = AnswerUdp(frame, packet.RemoteEndPoint);
            }
            catch (Exception e) when (e is SocketException or OperationCanceledException or ObjectDisposedException) { if (!life.IsCancellationRequested) Log?.Invoke("UDP control receive error: " + e.Message); }
            catch (Exception e) when (e is System.Text.Json.JsonException or InvalidDataException or ArgumentException) { /* Ignore malformed, unauthenticated datagrams. */ }
        }
    }
    private async Task AnswerUdp(Envelope frame, IPEndPoint remote)
    {
        try
        {
            var reply = await Dispatch(frame);
            byte[] bytes = Encoding.UTF8.GetBytes(Json.Write(auth.Create(frame.Id, true, frame.Command, Json.Write(reply))));
            if (!life.IsCancellationRequested && AcceptUdp) await udp!.SendAsync(bytes, remote, life.Token);
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException) { }
        finally { incoming.Release(); }
    }
    private async Task TcpLoop()
    {
        while (!life.IsCancellationRequested)
        {
            try
            {
                var client = await tcp!.AcceptTcpClientAsync(life.Token);
                if (!AcceptTcp || ((IPEndPoint)client.Client.RemoteEndPoint!).Address.ToString() != options.PeerAddress || !incoming.Wait(0)) { client.Dispose(); continue; }
                _ = AnswerTcp(client);
            }
            catch (Exception e) when (e is SocketException or OperationCanceledException or ObjectDisposedException) { if (!life.IsCancellationRequested) Log?.Invoke("TCP accept error: " + e.Message); }
        }
    }
    private async Task AnswerTcp(TcpClient client)
    {
        using (client)
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(life.Token))
        {
            timeout.CancelAfter(TimeSpan.FromSeconds(8));
            try
            {
                using var stream = client.GetStream();
                var frame = await Authenticator.ReadAsync(stream, timeout.Token);
                if (!auth.Verify(frame) || frame.Response) return;
                var reply = await Dispatch(frame);
                await Authenticator.WriteAsync(stream, auth.Create(frame.Id, true, frame.Command, Json.Write(reply)), timeout.Token);
            }
            catch (Exception e) when (e is IOException or SocketException or OperationCanceledException or System.Text.Json.JsonException or InvalidDataException or ArgumentException) { }
            finally { incoming.Release(); }
        }
    }
    private Task<PeerReply> Dispatch(Envelope frame)
    {
        long now = Environment.TickCount64;
        foreach (var entry in received.Where(p => now - p.Value.Created > 125_000 && p.Value.Reply.IsValueCreated && p.Value.Reply.Value.IsCompleted)) received.TryRemove(entry.Key, out _);
        if (received.Count >= 512 && !received.ContainsKey(frame.Id)) return Task.FromResult(new PeerReply(false, "", "Endpoint is busy; retry shortly."));
        var cached = received.GetOrAdd(frame.Id, _ => new Cached(now, frame.Command, frame.Payload, new Lazy<Task<PeerReply>>(async () =>
        {
            try { return new(true, frame.Command == PeerCommand.Ping ? "pong" : await handler(frame.Command, frame.Payload, life.Token)); }
            catch (Exception e) { return new(false, "", e.Message); }
        })));
        if (cached.Command != frame.Command || cached.Payload != frame.Payload) return Task.FromResult(new PeerReply(false, "", "Request ID was reused with different content."));
        return cached.Reply.Value;
    }
    private async Task HealthLoop()
    {
        try { while (!life.IsCancellationRequested) { await Probe(life.Token); await Task.Delay(3000, life.Token); } }
        catch (OperationCanceledException) { }
    }
    public async ValueTask DisposeAsync()
    {
        life.Cancel(); udp?.Dispose(); tcp?.Stop();
        foreach (var p in pending.Values) p.TrySetCanceled();
        try { await Task.WhenAll(loops).WaitAsync(TimeSpan.FromSeconds(10)); } catch (Exception e) when (e is OperationCanceledException or TimeoutException) { }
        life.Dispose();
    }
}
public sealed class PeerOperationException(string message) : Exception(message);
