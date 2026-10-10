using Elka.NetworkDiagnostics.Core;

namespace Elka.NetworkDiagnostics.Windows;

public interface ISystemRestoreBackend
{
    Task<IReadOnlyList<SystemRestorePoint>> List();
    Task Create(string description);
}

public sealed class WindowsSystemRestoreBackend : ISystemRestoreBackend
{
    // Use Windows PowerShell 5.1: these cmdlets are not part of PowerShell 7.
    public const string ListScript = "$points = @(Get-ComputerRestorePoint -ErrorAction Stop | ForEach-Object { [pscustomobject]@{SequenceNumber=[uint32]$_.SequenceNumber;Description=$_.Description;Created=([System.Management.ManagementDateTimeConverter]::ToDateTime($_.CreationTime).ToUniversalTime().ToString('O'))} }); ConvertTo-Json -InputObject $points -Depth 3";
    public static string CreateScript(string description) => "Checkpoint-Computer -Description " + Commands.Quote(description) + " -RestorePointType MODIFY_SETTINGS -ErrorAction Stop -WarningAction Stop";

    public async Task<IReadOnlyList<SystemRestorePoint>> List()
    {
        var result = await Commands.PowerShell(ListScript);
        Require(result);
        return Json.Read<List<SystemRestorePoint>>(result.Output);
    }

    public async Task Create(string description)
    {
        var result = await Commands.PowerShell(CreateScript(description), seconds: 600);
        Require(result);
    }

    private static void Require(CommandResult result)
    {
        if (result.ExitCode != 0) throw new InvalidOperationException("Windows could not confirm a restore point. Open System Protection to check that protection is enabled for the Windows drive and sufficient disk space is available. Windows may also limit automatic creation to one point per 24 hours. No repair was run.\n\n" + result.Combined);
    }
}

public sealed class RestorePoints(ISystemRestoreBackend backend, string root, Func<DateTimeOffset>? clock = null)
{
    private DateTimeOffset Now => clock?.Invoke() ?? DateTimeOffset.UtcNow;
    public string ReceiptPath => Path.Combine(root, "restore-point.json");
    public static string Description(Guid sessionId) => "Elka Network Diagnostics - before repairs " + sessionId.ToString("N");
    public static bool RequiredFor(string action) => action is "QosTrial" or "RestartAdapter" or "FlushDns" or "WinsockReset" or "IpReset";
    private static bool Fresh(SystemRestorePoint point, DateTimeOffset now) => point.Created <= now && now - point.Created < TimeSpan.FromHours(24);
    public static bool Eligible(RestorePointReceipt? receipt, Guid sessionId, DateTimeOffset now) =>
        sessionId != Guid.Empty && receipt?.Point != null && receipt.SessionId == sessionId &&
        receipt.Machine == Environment.MachineName && receipt.Point.Description == Description(sessionId) &&
        Fresh(receipt.Point, now);

    public async Task<RestorePointReceipt> CreateOrVerify(Guid sessionId)
    {
        if (sessionId == Guid.Empty) throw new InvalidDataException("A diagnostic session is required before creating a restore point.");
        string description = Description(sessionId);
        var before = await backend.List();
        // A verified session baseline can be reused after reopening the app. This also accepts
        // a point the operator explicitly created in System Protection with this exact name.
        var point = before.Where(p => p.Description == description && Fresh(p, Now)).OrderByDescending(p => p.Created).FirstOrDefault();
        if (point == null)
        {
            DateTimeOffset requested = Now;
            await backend.Create(description);
            var after = await backend.List();
            point = after.Where(p => p.Description == description && Fresh(p, Now) &&
                p.Created >= requested - TimeSpan.FromMinutes(2) && !before.Any(old => old.SequenceNumber == p.SequenceNumber))
                .OrderByDescending(p => p.Created).FirstOrDefault();
            if (point == null) throw new InvalidOperationException("Windows did not list a new restore point for this session. Repairs remain locked. Windows can skip automatic creation when a point was created in the last 24 hours. Open System Protection, create a point using the copied restore point name, then click Create / verify again.");
        }
        var receipt = new RestorePointReceipt(sessionId, Environment.MachineName, point, Now);
        Directory.CreateDirectory(root);
        SessionStore.AtomicWrite(ReceiptPath, receipt);
        return receipt;
    }

    public async Task<RestorePointReceipt?> RequireFor(string action, Guid sessionId)
    {
        if (!RequiredFor(action)) return null; // Capture and emergency rollback must remain available.
        var receipt = SessionStore.ReadOr<RestorePointReceipt>(ReceiptPath);
        if (!Eligible(receipt, sessionId, Now)) throw new InvalidOperationException("Repair blocked. First create and verify a Windows restore point for this session in Admin tools (valid for 24 hours).");
        var points = await backend.List();
        if (!points.Any(p => p == receipt!.Point)) throw new InvalidOperationException("Repair blocked: Windows no longer lists the recorded restore point. Create and verify a new point before repairing.");
        return receipt;
    }
}
