using System.Net;
using System.Net.Sockets;
using System.Text;
using Elka.NetworkDiagnostics.Core;

namespace Elka.NetworkDiagnostics.Network;

public record DiscoveredPeer(string Machine, string Address, int ControlPort)
{
    public override string ToString() => $"{Machine}  ·  {Address}  ·  control port {ControlPort}";
}
public sealed class Discovery : IAsyncDisposable
{
    public const int Port = 47829;
    private const string Query = "ELKA-NET-DIAG-DISCOVER/1";
    private readonly string address;
    private readonly int controlPort;
    private readonly CancellationTokenSource life = new();
    private UdpClient? listener;
    private Task? loop;
    public Discovery(string address, int controlPort) { this.address = address; this.controlPort = controlPort; }
    public void Start()
    {
        listener = new UdpClient(AddressFamily.InterNetwork); listener.Client.ExclusiveAddressUse = true;
        listener.Client.Bind(new IPEndPoint(IPAddress.Any, Port)); loop = Listen();
    }
    private async Task Listen()
    {
        long lastResponse = 0;
        try
        {
            while (!life.IsCancellationRequested)
            {
                var packet = await listener!.ReceiveAsync(life.Token);
                if (packet.Buffer.Length != Query.Length || Encoding.UTF8.GetString(packet.Buffer) != Query || Environment.TickCount64 - lastResponse < 200) continue;
                lastResponse = Environment.TickCount64;
                byte[] reply = Encoding.UTF8.GetBytes("ELKA1:" + Json.Write(new DiscoveredPeer(Environment.MachineName, address, controlPort)));
                await listener.SendAsync(reply, packet.RemoteEndPoint, life.Token);
            }
        }
        catch (Exception e) when (e is SocketException or OperationCanceledException or ObjectDisposedException) { }
    }
    public static async Task<List<DiscoveredPeer>> Find(string address, string mask, CancellationToken ct)
    {
        var a = IPAddress.Parse(address).GetAddressBytes(); var m = IPAddress.Parse(mask).GetAddressBytes();
        var broadcast = new IPAddress(a.Zip(m, (x, y) => (byte)(x | ~y)).ToArray());
        using var socket = new UdpClient(new IPEndPoint(IPAddress.Parse(address), 0)) { EnableBroadcast = true };
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(1800);
        var peers = new Dictionary<string, DiscoveredPeer>();
        await socket.SendAsync(Encoding.UTF8.GetBytes(Query), new IPEndPoint(broadcast, Port), ct);
        try
        {
            while (!deadline.IsCancellationRequested)
            {
                var packet = await socket.ReceiveAsync(deadline.Token);
                if (packet.Buffer.Length > 1024) continue;
                string text = Encoding.UTF8.GetString(packet.Buffer);
                if (!text.StartsWith("ELKA1:", StringComparison.Ordinal)) continue;
                try
                {
                    var peer = Json.Read<DiscoveredPeer>(text[6..]);
                    if (peer.Machine == null || peer.Address == address || peer.Address != packet.RemoteEndPoint.Address.ToString() || peer.Machine.Length > 100 || peer.ControlPort is < 1024 or > 65535) continue;
                    peers[peer.Address] = peer;
                }
                catch (Exception e) when (e is System.Text.Json.JsonException or InvalidDataException) { }
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
        return peers.Values.ToList();
    }
    public async ValueTask DisposeAsync() { life.Cancel(); listener?.Dispose(); if (loop != null) await loop; life.Dispose(); }
}
