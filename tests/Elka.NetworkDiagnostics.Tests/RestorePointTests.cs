using Elka.NetworkDiagnostics.Core;
using Elka.NetworkDiagnostics.Windows;

internal static class RestorePointTests
{
    public static async Task Run(string testRoot, Action<bool, string> check, Func<Func<Task>, string, Task> throws)
    {
        string root = Path.Combine(testRoot, "restore-points");
        Guid session = Guid.NewGuid();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var backend = new FakeRestoreBackend();
        var service = new RestorePoints(backend, root, () => now);
        foreach (string action in new[] { "WinsockReset", "IpReset", "QosTrial", "RestartAdapter", "FlushDns" })
            await throws(() => service.RequireFor(action, session), action + " blocked before a restore point exists");
        foreach (string action in new[] { "WfpAudit", "PacketCapture", "RestorePending" })
            check(await service.RequireFor(action, session) == null, action + " available without blocking evidence or emergency recovery");
        await throws(() => service.CreateOrVerify(Guid.Empty), "empty restore session rejected");
        backend.Creation = _ => throw new IOException("System protection is disabled.");
        await throws(() => service.CreateOrVerify(session), "disabled or failed Windows restore creation reported");
        check(!File.Exists(service.ReceiptPath), "failed creation never saves a success receipt");
        backend.Points.Add(new(10, "Unrelated Windows update point", now));
        backend.Creation = _ => { };
        await throws(() => service.CreateOrVerify(session), "Windows success without a matching point does not unlock repairs");
        check(!File.Exists(service.ReceiptPath), "24-hour skip leaves no verified receipt");
        backend.Creation = description => backend.Points.Add(new(11, description, now));
        var receipt = await service.CreateOrVerify(session);
        check(receipt.Point.SequenceNumber == 11 && receipt.SessionId == session, "new Windows point read back and bound to current session");
        check((await service.RequireFor("WinsockReset", session))?.Point.SequenceNumber == 11, "repair guard accepts matching live Windows point");
        int creates = backend.Creates;
        check((await service.CreateOrVerify(session)).Point == receipt.Point && backend.Creates == creates, "same-session baseline reused without claiming a new point");
        var reopened = new RestorePoints(backend, root, () => now);
        check((await reopened.RequireFor("IpReset", session))?.Point == receipt.Point, "app restart preserves baseline and rechecks Windows");
        await throws(() => service.RequireFor("IpReset", Guid.NewGuid()), "new session cannot inherit another session baseline");
        backend.Points.Remove(receipt.Point);
        await throws(() => service.RequireFor("IpReset", session), "deleted Windows point blocks repair even with a saved receipt");
        backend.Points.Add(receipt.Point with { Description = "Different point" });
        await throws(() => service.RequireFor("IpReset", session), "same sequence number with different contents rejected");
        backend.Points.RemoveAll(p => p.SequenceNumber == 11);
        backend.Points.Add(receipt.Point);
        backend.ListFailure = true;
        await throws(() => service.RequireFor("IpReset", session), "Windows verification failure blocks repair");
        backend.ListFailure = false;
        SessionStore.AtomicWrite(service.ReceiptPath, receipt with { Machine = "a different PC" });
        await throws(() => service.RequireFor("IpReset", session), "receipt from another machine rejected");
        SessionStore.AtomicWrite(service.ReceiptPath, receipt);
        now += TimeSpan.FromHours(24);
        await throws(() => service.RequireFor("IpReset", session), "24-hour baseline expiry blocks a later repair");
        backend.Creation = _ => { };
        await throws(() => service.CreateOrVerify(session), "stale same-name point cannot masquerade as newly created");
        backend.Creation = name => backend.Points.Add(new(12, name, now));
        var refreshed = await service.CreateOrVerify(session);
        check(refreshed.Point.SequenceNumber == 12, "expired baseline replaced by a newly verified point");
        now -= TimeSpan.FromMinutes(1);
        await throws(() => service.RequireFor("IpReset", session), "future-dated baseline rejected after clock rollback");
        now += TimeSpan.FromMinutes(1);
        await File.WriteAllTextAsync(service.ReceiptPath, "{broken");
        await throws(() => service.RequireFor("IpReset", session), "corrupt receipt cannot unlock a repair");
        Guid manualSession = Guid.NewGuid();
        backend.Points.Add(new(13, RestorePoints.Description(manualSession), now));
        creates = backend.Creates;
        check((await service.CreateOrVerify(manualSession)).Point.SequenceNumber == 13 && backend.Creates == creates,
            "manually created named point verified without another creation attempt");

        // Test Windows PowerShell 5.1 JSON/date mapping with a local replacement for the
        // read-only cmdlet. No restore creation or elevation is invoked by this harness.
        string fixture = "function Get-ComputerRestorePoint { [pscustomobject]@{SequenceNumber=42;Description='Fixture point';CreationTime='20261010090000.000000+000'} }; ";
        var mapped = await Commands.PowerShell(fixture + WindowsSystemRestoreBackend.ListScript);
        check(mapped.ExitCode == 0 && Json.Read<List<SystemRestorePoint>>(mapped.Output).Single().Created == DateTimeOffset.Parse("2026-10-10T09:00:00Z"), "Windows PowerShell singleton and DMTF date mapped correctly");
        var empty = await Commands.PowerShell("function Get-ComputerRestorePoint { }; " + WindowsSystemRestoreBackend.ListScript);
        check(empty.ExitCode == 0 && Json.Read<List<SystemRestorePoint>>(empty.Output).Count == 0, "empty Windows restore list preserved as an empty array");
        string createScript = WindowsSystemRestoreBackend.CreateScript("Elka's fixture");
        var parsed = await Commands.PowerShell("$tokens=$null; $errors=$null; [System.Management.Automation.Language.Parser]::ParseInput(" + Commands.Quote(createScript) + ", [ref]$tokens, [ref]$errors) | Out-Null; if ($errors.Count) { throw 'Invalid create script' }; 'Parsed only'");
        check(parsed.ExitCode == 0 && parsed.Output.Trim() == "Parsed only", "creation script parses with escaped text without executing it");
    }

    private sealed class FakeRestoreBackend : ISystemRestoreBackend
    {
        public List<SystemRestorePoint> Points { get; } = [];
        public Action<string> Creation { get; set; } = _ => { };
        public int Creates { get; private set; }
        public bool ListFailure { get; set; }
        public Task<IReadOnlyList<SystemRestorePoint>> List() => ListFailure
            ? throw new IOException("Windows query denied.") : Task.FromResult<IReadOnlyList<SystemRestorePoint>>(Points.ToArray());
        public Task Create(string description) { Creates++; Creation(description); return Task.CompletedTask; }
    }
}
