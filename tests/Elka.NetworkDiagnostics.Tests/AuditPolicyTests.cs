using Elka.NetworkDiagnostics.Core;
using Elka.NetworkDiagnostics.Windows;

internal static class AuditPolicyTests
{
    public static async Task Run(Action<bool, string> check, Func<Func<Task>, string, Task> throws)
    {
        // Model the documented Windows setter semantics; no real audit policy is changed.
        uint current = 0, lastWrite = 99;
        void Write(uint flags) { lastWrite = flags; if (flags != 0) current = flags == 4 ? 0 : flags; }
        AuditPolicyState.ApplyAndVerify(AuditPolicyState.IncludeFailure(current), Write, () => current);
        check(current == 2, "WFP trial enables failure auditing from an unaudited baseline");
        AuditPolicyState.ApplyAndVerify(0, Write, () => current);
        check(lastWrite == 4 && current == 0, "saved zero audit state restores with explicit NONE instead of UNCHANGED");
        foreach (uint original in new uint[] { 0, 1, 2, 3, 4 })
        {
            current = AuditPolicyState.Effective(original);
            AuditPolicyState.ApplyAndVerify(AuditPolicyState.IncludeFailure(original), Write, () => current);
            AuditPolicyState.ApplyAndVerify(original, Write, () => current);
            check(current == AuditPolicyState.Effective(original), $"audit trial restores original flags {original}");
        }
        AuditPolicyState.ApplyAndVerify(0, Write, () => 4);
        check(lastWrite == 4, "explicit NONE readback is equivalent to queried no-audit zero");
        await throws(() => Task.Run(() => AuditPolicyState.ApplyAndVerify(0, _ => { }, () => 2)), "policy that refuses restoration still fails readback");
        await throws(() => Task.Run(() => AuditPolicyState.ApplyAndVerify(1, _ => { }, () => 3)), "unexpected failure auditing cannot pass success-only readback");
        await throws(() => Task.Run(() => AuditPolicyState.ApplyAndVerify(0, _ => throw new UnauthorizedAccessException(), () => 0)), "audit setter denial propagates for recovery preservation");
        bool written = false;
        await throws(() => Task.Run(() => AuditPolicyState.ApplyAndVerify(8, _ => written = true, () => 0)), "unknown saved audit flags rejected");
        check(!written, "unknown flags cannot write an unintended audit policy");
        await throws(() => Task.Run(() => AuditPolicyState.ApplyAndVerify(5, _ => { }, () => 0)), "contradictory audit flags rejected");
        var record = new RecoveryRecord("WfpAudit", Guid.NewGuid().ToString(), null, 0, DateTimeOffset.UtcNow);
        check(RecoveryGuidance.Describe(record).Contains("audit cleanup"), "pending WFP cleanup identified without suggesting a network reset");
        check(RecoveryGuidance.Describe(record with { Action = "IpReset", RebootRequired = true }).Contains("Acknowledge reboot"), "reboot records get the appropriate recovery instruction");
        check(RecoveryGuidance.Describe(null).Contains("do not delete"), "unknown recovery journal never recommends deleting the safeguard");
        var tracing = new DiagnosticAssessment(new("id", "Ethernet", "fixture", "192.0.2.1", "255.255.255.0", "", "Up", false), "192.0.2.2", 47830, 47831) { IsFullScan = false };
        var advice = Recommendations.Analyze(tracing);
        check(advice.Any(r => r.Title.Contains("tracing attempt")) && !advice.Any(r => r.Title == "Finish the missing two-PC tests"), "blocked standalone trace does not imply previously working endpoints need re-pairing");
        check(Recommendations.Report(tracing, advice).Contains("Scope: Packet tracing only"), "standalone report makes its limited scope explicit");
    }
}
