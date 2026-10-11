using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Elka.NetworkDiagnostics.Core;

namespace Elka.NetworkDiagnostics.Network;

public enum PeerCommand { Ping, Summary, PrepareTest, SendTest, FinishTest, BeginCheck, UpdateCheck, EndCheck, CancelCheck }
public record Envelope(int Version, Guid Id, bool Response, PeerCommand Command, long Time, string Payload, string Signature);
public record PeerReply(bool Ok, string Payload, string Error = "");
public record PeerSummary(string Machine, string Address, string Role, string Version = "0.2.2", bool SharedCheck = false);
public record PeerOptions(string Address, string PeerAddress, string PairingCode, string Role, int ControlPort = 47830, int PeerControlPort = 47830, int TestPort = 47831, int PeerTestPort = 47831);
public record TransportHealth(bool Udp, bool Tcp, string Active, DateTimeOffset Checked, string Detail);

public sealed class Authenticator
{
    private readonly byte[] key;
    public const int MaxFrame = 48_000;
    public Authenticator(string code)
    {
        if (code.Length != 32 || !code.All(Uri.IsHexDigit)) throw new ArgumentException("Use the same 32-character pairing code on both PCs.");
        key = SHA256.HashData(Convert.FromHexString(code));
    }
    public static string NewCode() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
    public Envelope Create(Guid id, bool response, PeerCommand command, string payload)
    {
        var e = new Envelope(1, id, response, command, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), payload, "");
        return e with { Signature = Convert.ToHexString(HMACSHA256.HashData(key, Canonical(e))) };
    }
    public bool Verify(Envelope e)
    {
        if (e.Version != 1 || !Enum.IsDefined(e.Command) || e.Id == Guid.Empty || e.Payload == null || e.Signature == null || e.Payload.Length > 40_000 || e.Signature.Length != 64) return false;
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        if (e.Time < now - 60_000 || e.Time > now + 60_000) return false;
        try { return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(e.Signature), HMACSHA256.HashData(key, Canonical(e))); }
        catch (FormatException) { return false; }
    }
    private static byte[] Canonical(Envelope e) => Encoding.UTF8.GetBytes($"{e.Version}\n{e.Id:D}\n{e.Response}\n{(int)e.Command}\n{e.Time}\n{e.Payload}");
    public static async Task WriteAsync(Stream stream, Envelope envelope, CancellationToken ct)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(Json.Write(envelope));
        if (bytes.Length > MaxFrame) throw new InvalidDataException("Control message too large.");
        byte[] size = new byte[4]; BinaryPrimitives.WriteInt32BigEndian(size, bytes.Length);
        await stream.WriteAsync(size, ct); await stream.WriteAsync(bytes, ct);
    }
    public static async Task<Envelope> ReadAsync(Stream stream, CancellationToken ct)
    {
        byte[] size = new byte[4]; await stream.ReadExactlyAsync(size, ct);
        int length = BinaryPrimitives.ReadInt32BigEndian(size);
        if (length <= 0 || length > MaxFrame) throw new InvalidDataException("Invalid control frame length.");
        byte[] bytes = new byte[length]; await stream.ReadExactlyAsync(bytes, ct);
        return Json.Read<Envelope>(Encoding.UTF8.GetString(bytes));
    }
}
