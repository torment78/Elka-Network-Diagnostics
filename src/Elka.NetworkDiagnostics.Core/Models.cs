using System.IO.Compression;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Elka.NetworkDiagnostics.Core;

public static class Json
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web) { WriteIndented = false, Converters = { new JsonStringEnumConverter() } };
    public static string Write<T>(T value) => JsonSerializer.Serialize(value, Options);
    public static T Read<T>(string value) => JsonSerializer.Deserialize<T>(value, Options) ?? throw new InvalidDataException("Empty document.");
}

public enum Outcome { Passed, Failed, Inconclusive, Information }
public record Evidence(DateTimeOffset Time, string Stage, Outcome Outcome, string Summary, string Details, string Machine, Guid? TestId = null)
{
    public static Evidence Create(string stage, Outcome outcome, string summary, string details = "", Guid? testId = null) => new(DateTimeOffset.UtcNow, stage, outcome, summary, details, Environment.MachineName, testId);
}
public record AdapterInfo(string Id, string Name, string Description, string Address, string Mask, string Gateway, string Status, bool IsVirtual)
{
    public string Label => $"{Name}  ·  {Address}";
    public override string ToString() => Label;
}
// Role stays in persisted/wire data for compatibility with earlier releases.
// Both PCs use the same neutral value; it never selects tests or fault attribution.
public record AppSettings(string AdapterId = "", string PeerAddress = "", string Role = "Endpoint", int ControlPort = 47830, int TestPort = 47831);
public record DiagnosticSession(Guid Id, DateTimeOffset Started, string Machine, string Role, List<Evidence> Evidence);
public record HelperRequest(string Action, string AdapterId, int Port, string Address, Guid SessionId = default, string PeerAddress = "");
public record HelperMessage(string Kind, string Text, string? Artifact = null);
public record RecoveryRecord(string Action, string AdapterId, bool? OriginalEnabled, uint? AuditFlags, DateTimeOffset Created, bool RebootRequired = false);
public record SystemRestorePoint(uint SequenceNumber, string Description, DateTimeOffset Created);
public record RestorePointReceipt(Guid SessionId, string Machine, SystemRestorePoint Point, DateTimeOffset Verified);

public static class RecoveryGuidance
{
    public static string Describe(RecoveryRecord? record) => record switch
    {
        { RebootRequired: true } => $"A previous {record.Action} requires a Windows reboot. After restarting, select Acknowledge reboot and retest. Restore pending change cannot undo this reset.",
        { Action: "WfpAudit" } => "Packet-drop audit cleanup is pending from an earlier WFP capture. In Admin tools, select Restore pending change to restore and verify the original audit policy, then retry Packet tracing. This is diagnostic cleanup, not a network reset.",
        { Action: "QosTrial" } => "A previous QoS trial needs cleanup. In Admin tools, select Restore pending change to restore the adapter's recorded QoS setting before another operation.",
        _ => "An unreadable or unknown recovery record is present. Export the evidence and inspect the record before making another change; do not delete it to bypass recovery."
    };
}

public sealed class SessionStore
{
    private readonly object gate = new();
    public string Root { get; }
    public DiagnosticSession Session { get; private set; }
    public event Action<Evidence>? Added;
    public SessionStore(string? root = null)
    {
        Root = root ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ElkaSoft", "NetworkDiagnostics");
        Directory.CreateDirectory(Root);
        Session = ReadOr<DiagnosticSession>(Path.Combine(Root, "session.json")) ?? new(Guid.NewGuid(), DateTimeOffset.UtcNow, Environment.MachineName, "Endpoint", []);
    }
    public void SetRole(string role) { lock (gate) { Session = Session with { Role = role }; Save(); } }
    public DiagnosticSession Snapshot() { lock (gate) return Session with { Evidence = [.. Session.Evidence] }; }
    public void Add(Evidence evidence)
    {
        lock (gate)
        {
            evidence = evidence with { Details = evidence.Details.Length <= 96_000 ? evidence.Details : evidence.Details[..96_000] + "\n[Evidence text truncated.]" };
            Session.Evidence.Add(evidence);
            while (Session.Evidence.Count > 500 || Session.Evidence.Sum(e => e.Details.Length + e.Summary.Length) > 1_000_000) Session.Evidence.RemoveAt(0);
            Save();
        }
        Added?.Invoke(evidence);
    }
    public void NewSession(string role) { lock (gate) { Session = new(Guid.NewGuid(), DateTimeOffset.UtcNow, Environment.MachineName, role, []); Save(); } }
    public AppSettings LoadSettings() => ReadOr<AppSettings>(Path.Combine(Root, "settings.json")) ?? new();
    public void SaveSettings(AppSettings settings) => AtomicWrite(Path.Combine(Root, "settings.json"), settings);
    public string Export(string destination)
    {
        DiagnosticSession snapshot;
        lock (gate) snapshot = Session with { Evidence = [.. Session.Evidence] };
        using var zip = ZipFile.Open(destination, ZipArchiveMode.Create);
        WriteEntry(zip, "session.json", Json.Write(snapshot));
        var lines = new List<string> { "ELKA NETWORK DIAGNOSTICS", $"Session: {snapshot.Id}", $"Machine: {snapshot.Machine}", $"Started (UTC): {snapshot.Started:u}", "", "Both PCs can send, receive and initiate checks. Results describe recorded tests only. NIC observation requires capture evidence; socket tests do not establish NIC observations.", "" };
        foreach (var e in snapshot.Evidence) lines.Add($"[{e.Time:u}] {e.Stage} / {e.Outcome}\n{e.Summary}\n{e.Details}\n");
        WriteEntry(zip, "summary.txt", string.Join(Environment.NewLine, lines));
        string captures = Path.Combine(Root, "captures");
        List<string> manifest = ["CAPTURE EXPORT CONTENTS", "Only captures referenced by this session are considered.",
            "Limits: 50 files, 512 MiB total; PktMon text up to 512 MiB, other files under 100 MiB.",
            "Oversized PktMon text can be regenerated from its ETL with pktmon etl2txt <file.etl> --out <file.txt> --hex.", ""];
        long exportedBytes = 0; int exportedFiles = 0;
        if (Directory.Exists(captures))
        {
            foreach (string path in Directory.EnumerateFiles(captures)
                .Where(path => snapshot.Evidence.Any(e => e.Details.Contains(path, StringComparison.OrdinalIgnoreCase)))
                // Keep source ETLs and compact companions ahead of expanded hex text.
                .OrderBy(path => path.EndsWith("-pktmon.txt", StringComparison.OrdinalIgnoreCase))
                .ThenByDescending(File.GetLastWriteTimeUtc))
            {
                long size = new FileInfo(path).Length;
                bool expandedText = path.EndsWith("-pktmon.txt", StringComparison.OrdinalIgnoreCase);
                string reason = size >= (expandedText ? 512L : 100L) * 1024 * 1024 ? "file size limit" :
                    exportedFiles >= 50 ? "50-file limit" : exportedBytes + size > 512L * 1024 * 1024 ? "total size limit" : "";
                if (reason != "") { manifest.Add($"OMITTED ({reason}): {path} ({size} bytes)"); continue; }
                zip.CreateEntryFromFile(path, "captures/" + Path.GetFileName(path), CompressionLevel.Fastest);
                exportedBytes += size; exportedFiles++;
                manifest.Add($"INCLUDED: captures/{Path.GetFileName(path)} ({size} bytes)");
            }
        }
        WriteEntry(zip, "captures-manifest.txt", string.Join(Environment.NewLine, manifest));
        return destination;
    }
    public DiagnosticSession Import(string path)
    {
        using var zip = ZipFile.OpenRead(path);
        var entry = zip.GetEntry("session.json") ?? throw new InvalidDataException("No session.json in this report.");
        if (entry.Length > 8_000_000) throw new InvalidDataException("Report exceeds 8 MB.");
        using var reader = new StreamReader(entry.Open());
        var text = new System.Text.StringBuilder(); char[] chunk = new char[4096]; int count;
        while ((count = reader.Read(chunk, 0, chunk.Length)) > 0)
        {
            if (text.Length + count > 8_000_000) throw new InvalidDataException("Expanded report exceeds the import limit.");
            text.Append(chunk, 0, count);
        }
        var report = Json.Read<DiagnosticSession>(text.ToString());
        if (report.Evidence == null || report.Evidence.Count > 500) throw new InvalidDataException("Invalid or oversized evidence collection.");
        return report;
    }
    public static T? ReadOr<T>(string path) where T : class
    {
        try { return File.Exists(path) ? Json.Read<T>(File.ReadAllText(path)) : null; }
        catch (Exception e) when (e is IOException or JsonException or InvalidDataException) { return null; }
    }
    public static void AtomicWrite<T>(string path, T value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string temp = path + ".tmp";
        File.WriteAllText(temp, Json.Write(value));
        File.Move(temp, path, true);
    }
    private void Save() => AtomicWrite(Path.Combine(Root, "session.json"), Session);
    private static void WriteEntry(ZipArchive zip, string name, string content) { using var writer = new StreamWriter(zip.CreateEntry(name).Open()); writer.Write(content); }
}
