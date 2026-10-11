using Elka.NetworkDiagnostics.Core;

namespace Elka.NetworkDiagnostics.Windows;

public interface ISystemRestoreBackend
{
    Task<IReadOnlyList<SystemRestorePoint>> List();
    Task Create(string description);
}

public sealed class WindowsSystemRestoreBackend(Func<string, int, Task<CommandResult>>? execute = null) : ISystemRestoreBackend
{
    private Task<CommandResult> Run(string script, int seconds = 45) => execute?.Invoke(script, seconds) ?? Commands.PowerShell(script, seconds: seconds);
    // Use Windows PowerShell 5.1: these cmdlets are not part of PowerShell 7.
    public const string ListScript = "$points = @(Get-ComputerRestorePoint -ErrorAction Stop | ForEach-Object { [pscustomobject]@{SequenceNumber=[uint32]$_.SequenceNumber;Description=$_.Description;Created=([System.Management.ManagementDateTimeConverter]::ToDateTime($_.CreationTime).ToUniversalTime().ToString('O'))} }); ConvertTo-Json -InputObject $points -Depth 3";
    public static string CreateScript(string description) => "Checkpoint-Computer -Description " + Commands.Quote(description) + " -RestorePointType MODIFY_SETTINGS -ErrorAction Stop -WarningAction Stop";

    // Each read is independent: an unavailable WMI provider must not hide OS, policy or disk evidence.
    public const string DiagnosticsScript = """
        'READ-ONLY RESTORE DIAGNOSTICS';
        'PowerShell: ' + $PSVersionTable.PSVersion; 'Culture: ' + [cultureinfo]::CurrentCulture.Name; 'UI culture: ' + [cultureinfo]::CurrentUICulture.Name;
        $reads = @(
          @{Name='Windows'; Read={Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,ProductType | Format-List}},
          @{Name='Elevation'; Read={([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}},
          @{Name='Windows drive space (bytes)'; Read={Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='" + $env:SystemDrive + "'") | Select-Object DeviceID,FreeSpace,Size | Format-List}},
          @{Name='VSS services (Stopped alone is not an error)'; Read={Get-CimInstance Win32_Service -Filter "Name='VSS' OR Name='swprv'" | Select-Object Name,State,StartMode | Format-List}},
          @{Name='System Restore policy'; Read={if (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore') {Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore' | Select-Object DisableSR,DisableConfig | Format-List} else {'No System Restore policy key.'}}},
          @{Name='Creation frequency override'; Read={Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' | Select-Object SystemRestorePointCreationFrequency | Format-List}},
          @{Name='Latest Windows restore points'; Read={Get-ComputerRestorePoint -ErrorAction Stop | Sort-Object SequenceNumber -Descending | Select-Object -First 5 SequenceNumber,Description,CreationTime | Format-List}}
        );
        foreach ($read in $reads) { $read.Name; try { & $read.Read | Out-String -Width 180 } catch { 'Unavailable: ' + $_.Exception.Message; 'Error ID: ' + $_.FullyQualifiedErrorId } }
        """;

    public async Task<IReadOnlyList<SystemRestorePoint>> List()
    {
        var result = await Run(ListScript);
        if (result.ExitCode != 0) throw await Failure("reading Windows restore points", result);
        try { return Json.Read<List<SystemRestorePoint>>(result.Output); }
        catch (Exception e) when (e is System.Text.Json.JsonException or InvalidDataException)
        { throw await Failure("decoding the Windows restore-point list", result); }
    }

    public async Task Create(string description)
    {
        var result = await Run(CreateScript(description), 600);
        if (result.ExitCode != 0) throw await Failure("creating the Windows restore point", result);
    }

    private async Task<InvalidOperationException> Failure(string phase, CommandResult result)
    {
        string diagnostics;
        try { diagnostics = (await Run(DiagnosticsScript)).Combined; }
        catch (Exception e) { diagnostics = "Read-only diagnostics unavailable: " + e.Message; }
        return new InvalidOperationException($"Windows restore point was not confirmed while {phase}.\n\n" +
            "No network repair was run. Diagnostics and packet capture remain available without a restore point.\n\n" +
            "WHAT TO CHECK\nOpen System Protection and check protection on the Windows drive and available disk space. " +
            "Windows can limit automatic creation to one point per 24 hours. If a point was created recently, use Copy restore point name, " +
            "create that named point in System Protection, then return to Create / verify. " +
            "If Windows itself fails, retain its error code; policy, VSS or WMI problems may need attention. " +
            "System Restore requires a supported Windows client edition. These are possible causes, not a diagnosis of this PC.\n\n" +
            $"WINDOWS RESULT\nPhase: {phase}\nExit code: {result.ExitCode}\n{Bound(result.Combined)}\n\n{Bound(diagnostics)}");
    }
    private static string Bound(string value) => value.Length <= 12_000 ? value : value[..12_000] + "\n[Details truncated.]";
}

public sealed class RestorePoints(ISystemRestoreBackend backend, string root, Func<DateTimeOffset>? clock = null, Func<string, Task>? progress = null)
{
    private Task Report(string text) => progress?.Invoke(text) ?? Task.CompletedTask;
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
        await Report("Reading existing Windows restore points…");
        var before = await backend.List();
        // A verified session baseline can be reused after reopening the app. This also accepts
        // a point the operator explicitly created in System Protection with this exact name.
        var point = before.Where(p => p.Description == description && Fresh(p, Now)).OrderByDescending(p => p.Created).FirstOrDefault();
        if (point == null)
        {
            DateTimeOffset requested = Now;
            await Report("Asking Windows to create a restore point… This can take several minutes.");
            Exception? creationFailure = null;
            try { await backend.Create(description); }
            catch (Exception e) { creationFailure = e; }
            await Report("Verifying the restore point in Windows… A successful command alone is not enough.");
            IReadOnlyList<SystemRestorePoint> after;
            try { after = await backend.List(); }
            catch (Exception e) when (creationFailure != null)
            { throw new InvalidOperationException(creationFailure.Message + "\n\nVERIFICATION ALSO FAILED\n" + e.Message, e); }
            point = after.Where(p => p.Description == description && Fresh(p, Now) &&
                p.Created >= requested - TimeSpan.FromMinutes(2) && !before.Any(old => old.SequenceNumber == p.SequenceNumber))
                .OrderByDescending(p => p.Created).FirstOrDefault();
            if (point == null) throw new InvalidOperationException(creationFailure?.Message ?? "Windows did not list a new restore point for this session. Repairs remain locked. Windows can skip automatic creation when a point was created in the last 24 hours. Open System Protection, create a point using the copied restore point name, then click Create / verify again. Diagnostics and packet capture remain available.", creationFailure);
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
