using System.Net;
using System.Net.Sockets;
using System.Text;
using Elka.NetworkDiagnostics.Core;
using Elka.NetworkDiagnostics.Network;
using Elka.NetworkDiagnostics.Windows;

int checks = 0;
void Check(bool value, string name) { if (!value) throw new Exception("FAIL: " + name); checks++; Console.WriteLine("PASS " + name); }
async Task Throws(Func<Task> action, string name) { bool failed = false; try { await action(); } catch { failed = true; } Check(failed, name); }
int FreePort() { var l = new TcpListener(IPAddress.Loopback, 0); l.Start(); int p = ((IPEndPoint)l.LocalEndpoint).Port; l.Stop(); return p; }

string code = Authenticator.NewCode();
var auth = new Authenticator(code);
var envelope = auth.Create(Guid.NewGuid(), false, PeerCommand.Summary, "{}");
Check(auth.Verify(envelope), "authenticated envelope");
Check(!auth.Verify(envelope with { Payload = "tampered" }), "payload tampering rejected");
Check(!auth.Verify(envelope with { Command = PeerCommand.SendTest }), "command tampering rejected");
Check(!auth.Verify(envelope with { Time = 1 }), "expired envelope rejected");
Check(!auth.Verify(envelope with { Payload = null! }), "null payload rejected");
Check(!new Authenticator(Authenticator.NewCode()).Verify(envelope), "wrong pairing code rejected");
await Throws(() => Task.FromResult(new Authenticator("123456")), "short pairing code rejected");
await Throws(() => Task.Run(() => SocketTests.Validate(new("UDP", 1_000_000))), "unbounded test rejected");
await Throws(() => Task.Run(() => Commands.AdapterScript("x';Remove-Item C:\\;#")), "adapter command injection rejected");
using (var malformed = new MemoryStream(new byte[] { 0x7f, 0xff, 0xff, 0xff })) await Throws(() => Authenticator.ReadAsync(malformed, default), "oversized TCP frame rejected before allocation");

int pa = FreePort(), pb = FreePort(), ta = FreePort(), tb = FreePort();
var oa = new PeerOptions("127.0.0.1", "127.0.0.1", code, "Endpoint", pa, pb, ta, tb);
var ob = new PeerOptions("127.0.0.1", "127.0.0.1", code, "Endpoint", pb, pa, tb, ta);
await using var sa = new SocketTests(oa); await using var sb = new SocketTests(ob);
int handled = 0; bool rejectFinish = false;
async Task<string> Handler(PeerCommand cmd, string payload, CancellationToken ct)
{
    if (cmd == PeerCommand.Summary && payload == "\"slow\"") { Interlocked.Increment(ref handled); await Task.Delay(2700, ct); return "once"; }
    if (cmd == PeerCommand.FinishTest && rejectFinish) { await sb.Handle(cmd, payload, ct); throw new IOException("Simulated receiver result unavailable"); }
    return await sb.Handle(cmd, payload, ct);
}
await using var a = new PeerService(oa, sa.Handle); await using var b = new PeerService(ob, Handler);
a.Start(); b.Start();
var health = await a.Probe(); Check(health.Udp && health.Tcp && health.Active == "UDP", "both control paths authenticated; UDP preferred");
Check(Json.Read<PeerSummary>(await a.Request(PeerCommand.Summary, new { })).Role == "Endpoint", "paired summary exchange with identical neutral endpoint labels");
Check(await a.Request(PeerCommand.Summary, "slow") == "once" && handled == 1, "UDP retries and TCP fallback execute one command only");
foreach (string protocol in new[] { "UDP", "TCP" })
{
    foreach (bool reverse in new[] { false, true })
    {
        var result = await sa.Run(a, protocol, reverse, default);
        Check(result.Passed && result.Receive.Received == 200, $"{protocol} {(reverse ? "reverse" : "forward")} real loopback delivery");
        Check(protocol == "UDP" ? result.Send.AverageRoundTripMs.HasValue : result.Send.AcknowledgedTransferMs.HasValue && !result.Send.AverageRoundTripMs.HasValue, $"{protocol} timing measured with correct semantics");
        Check(result.Detail.Contains("NIC observation") && result.Spec.Port == (reverse ? ta : tb), "flow-scoped evidence and explicit test port");
    }
}
foreach (string protocol in new[] { "UDP", "TCP" })
    foreach (bool reverse in new[] { false, true })
        Check((await sb.Run(b, protocol, reverse, default)).Passed, $"same-role second PC can initiate {protocol} {(reverse ? "reverse" : "forward")} real socket test");
using (var occupied = new UdpClient(new IPEndPoint(IPAddress.Loopback, tb)))
{
    TestAttemptException? failure = null;
    try { await sa.Run(a, "UDP", false, default); } catch (TestAttemptException e) { failure = e; }
    Check(failure?.Observation is { Outcome: Outcome.Inconclusive, Sent: null, Received: null } && failure.Observation.CoordinationIssue.Contains("could not prepare"),
        "occupied remote port identifies receiver preparation failure without inventing packet loss");
}
rejectFinish = true;
TestAttemptException? lostResult = null;
try { await sa.Run(a, "UDP", false, default); } catch (TestAttemptException e) { lostResult = e; }
finally { rejectFinish = false; }
Check(lostResult?.Observation is { Sent: 200, Received: null, Outcome: Outcome.Inconclusive } && lostResult.Observation.CoordinationIssue.Contains("receiver result"),
    "real sends remain recorded when the remote result exchange fails");
b.AcceptUdp = false;
health = await a.Probe(); Check(!health.Udp && health.Tcp && health.Active == "TCP", "UDP control loss selects TCP");
Check(Json.Read<PeerSummary>(await a.Request(PeerCommand.Summary, new { })).Address == "127.0.0.1", "requests continue over TCP");
var udpWithTcp = await sa.Run(a, "UDP", false, default); Check(udpWithTcp.Passed, "UDP test independent from broken UDP control");
b.AcceptUdp = true; b.AcceptTcp = false;
health = await a.Probe(); Check(health.Udp && !health.Tcp && health.Active == "UDP", "TCP loss selects UDP");
Check((await sa.Run(a, "TCP", true, default)).Passed, "TCP test coordinated over UDP control");
b.AcceptTcp = true;
using (var occupied = new UdpClient(new IPEndPoint(IPAddress.Loopback, tb))) await Throws(() => a.Request(PeerCommand.PrepareTest, new TestRequest("UDP")), "occupied receive port reported, not stolen");
var pending = await sb.Prepare(new("UDP", 3));
using (var attacker = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)))
{
    var badPacket = SocketTests.Packet(pending, 0); badPacket[20] ^= 1;
    await attacker.SendAsync(badPacket, new IPEndPoint(IPAddress.Loopback, tb));
    await attacker.SendAsync(SocketTests.Packet(pending, 2), new IPEndPoint(IPAddress.Loopback, tb));
    await attacker.SendAsync(SocketTests.Packet(pending, 2), new IPEndPoint(IPAddress.Loopback, tb));
    await attacker.SendAsync(SocketTests.Packet(pending, 0), new IPEndPoint(IPAddress.Loopback, tb));
    await Task.Delay(100);
}
var counted = await sb.Finish(pending.Id);
Check(counted.Received == 2 && counted.Duplicates == 1 && counted.OutOfOrder == 1, "invalid token ignored; duplicates, loss and ordering counted");
var noTraffic = await sb.Prepare(new("UDP", 2)); var empty = await sb.Finish(noTraffic.Id); Check(empty.Received == 0 && empty.Expected == 2, "no traffic never produces a pass");
await Throws(() => sb.Send(new(Guid.NewGuid(), code, "UDP", 53, 1, 100, 1), default), "peer cannot request traffic to an unapproved destination port");

await CoordinatedCheckTests.Run(Check);

string root = Path.Combine(AppContext.BaseDirectory, "test-data", Guid.NewGuid().ToString("N"));
var store = new SessionStore(root); store.Add(Evidence.Create("test", Outcome.Failed, "UDP reverse failed", "No packets at socket; NIC observation unavailable."));
store.SaveSettings(new("adapter", "127.0.0.1"));
string zip = Path.Combine(root, "report.zip"); store.Export(zip);
var imported = store.Import(zip); Check(imported.Id == store.Session.Id && imported.Evidence.Single().Outcome == Outcome.Failed, "offline report round trip preserves session and outcome");
Check(new SessionStore(root).Session.Id == store.Session.Id, "session resumes after process restart");
Check(!File.ReadAllText(Path.Combine(root, "settings.json")).Contains(code), "pairing secret excluded from settings");
Check(WindowsDiagnostics.Adapters().All(x => IPAddress.TryParse(x.Address, out _)), "Windows adapter discovery returns valid IPv4 addresses");
b.AcceptTcp = false; b.AcceptUdp = false;
var offline = await a.Probe(); Check(!offline.Udp && !offline.Tcp && offline.Active == "Offline", "both control paths fail without inventing a healthy route");
await Throws(() => a.Request(PeerCommand.Summary, new { }), "offline request fails with actionable error");
TestAttemptException? noControl = null;
try { await sa.Run(a, "UDP", false, default); } catch (TestAttemptException e) { noControl = e; }
Check(noControl?.Observation is { Outcome: Outcome.Inconclusive, Sent: null, Received: null } && !noControl.Observation.CoordinationIssue.Contains("could not prepare"),
    "unreachable control channel cannot be misreported as receiver refusal or UDP loss");
store.Add(Evidence.Create("offline", Outcome.Information, "Local diagnostics still record results"));
Check(store.Session.Evidence.Count == 2, "offline sessions still record local evidence");
await RestorePointTests.Run(root, Check, Throws);
TwoPcTests.Run(Check);
await RecommendationTests.Run(Check, Throws);
await AuditPolicyTests.Run(Check, Throws);
await PktmonTests.Run(root, Check, Throws);
PacketPathTests.Run(Check);
LocalizationTests.Run(Check);
int toolsArgument = Array.IndexOf(args, "--wireshark-tools");
await WiresharkTests.Run(root, Check, Throws, toolsArgument >= 0 && toolsArgument + 1 < args.Length ? args[toolsArgument + 1] : null);
int wfpArgument = Array.IndexOf(args, "--inspect-wfp");
if (wfpArgument >= 0 && wfpArgument + 1 < args.Length)
{
    var wfp = WfpState.Read(File.ReadAllText(args[wfpArgument + 1]));
    Check(wfp.Filters.Count > 0, "saved real Windows WFP fragment parsed without modifying Windows");
    Console.WriteLine($"SAVED WFP INSPECTION: {wfp.Filters.Count} filters, timestamp {wfp.Time:O}; no event attribution inferred.");
}
int setupArgument = Array.IndexOf(args, "--download-wireshark-installer");
if (setupArgument >= 0 && setupArgument + 1 < args.Length)
{
    string installer = await WiresharkSetup.Download(args[setupArgument + 1], _ => { }, default);
    Check(File.Exists(installer), "official installer download passed size, hash and publisher-signature validation; not launched");
    Console.WriteLine("VERIFIED INSTALLER (not launched): " + installer);
}
string exportRoot = Path.Combine(root, "capture-export");
var exportStore = new SessionStore(exportRoot);
string captureFolder = Path.Combine(exportRoot, "captures"); Directory.CreateDirectory(captureFolder);
for (int i = 0; i < 55; i++) File.WriteAllText(Path.Combine(captureFolder, $"old-{i}.txt"), "unreferenced");
string currentCapture = Path.Combine(captureFolder, "current-npcap.pcapng"); File.WriteAllText(currentCapture, "current capture fixture");
exportStore.Add(Evidence.Create("capture", Outcome.Information, "current", "Saved artifact: " + currentCapture));
string expandedCapture = Path.Combine(captureFolder, "large-pktmon.txt");
using (var expanded = File.Create(expandedCapture)) expanded.SetLength(100L * 1024 * 1024 + 1);
string oversizedCapture = Path.Combine(captureFolder, "oversized-pktmon.txt");
using (var oversized = File.Create(oversizedCapture)) oversized.SetLength(512L * 1024 * 1024);
exportStore.Add(Evidence.Create("capture", Outcome.Information, "expanded text fixtures", expandedCapture + "\n" + oversizedCapture));
string captureExport = Path.Combine(exportRoot, "current.zip"); exportStore.Export(captureExport);
using (var archive = System.IO.Compression.ZipFile.OpenRead(captureExport))
{
    Check(archive.GetEntry("captures/current-npcap.pcapng") != null && archive.Entries.All(e => !e.FullName.Contains("old-")), "current referenced captures export even when many older unreferenced files exist");
    Check(archive.GetEntry("captures/large-pktmon.txt")?.Length == 100L * 1024 * 1024 + 1, "expanded PktMon text above 100 MiB is included in the report ZIP");
    using var manifest = new StreamReader(archive.GetEntry("captures-manifest.txt")!.Open());
    string contents = manifest.ReadToEnd();
    Check(archive.GetEntry("captures/oversized-pktmon.txt") == null && contents.Contains("OMITTED (file size limit): " + oversizedCapture) && contents.Contains("INCLUDED: captures/large-pktmon.txt"),
        "ZIP manifest explicitly identifies included and oversized omitted captures");
}
int previewArgument = Array.IndexOf(args, "--write-path-preview");
if (previewArgument >= 0 && previewArgument + 1 < args.Length) PacketPathTests.WritePreview(args[previewArgument + 1]);
int captureArgument = Array.IndexOf(args, "--inspect-pktmon");
if (captureArgument >= 0 && captureArgument + 1 < args.Length)
{
    using var capturedText = new StreamReader(args[captureArgument + 1]);
    Console.WriteLine("SAVED PKTMON INSPECTION: " + Json.Write(PktmonText.Inspect(capturedText)));
}
if (args.Contains("--windows-inspection"))
{
    var local = WindowsDiagnostics.Adapters().First(x => x.Status == "Up" && !x.IsVirtual);
    var diagnostics = new WindowsDiagnostics();
    foreach (int stage in new[] { 1, 4, 5, 6 })
    {
        var result = await diagnostics.Collect(stage, local, local.Address, 47830, 47831, default);
        await File.WriteAllTextAsync(Path.Combine(root, $"windows-stage-{stage}.txt"), result.Details);
        Check(result.Details.Length > 20, $"Windows stage {stage} returns inspection evidence");
        Check(!result.Details.Contains("ParserError", StringComparison.OrdinalIgnoreCase), $"Windows stage {stage} script parses");
        Check(!result.Details.Contains("Selected adapter is no longer present", StringComparison.OrdinalIgnoreCase), $"Windows stage {stage} resolves the actual adapter identity");
        Console.WriteLine($"INSPECTION {stage}: {result.Outcome} — {result.Summary}");
    }
    Console.WriteLine("Inspection evidence: " + root);
}
Console.WriteLine($"\n{checks} checks passed. Real two-PC, firewall and elevated repair validation remain manual.");
