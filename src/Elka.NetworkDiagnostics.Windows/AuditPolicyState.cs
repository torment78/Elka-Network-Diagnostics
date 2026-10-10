namespace Elka.NetworkDiagnostics.Windows;

public static class AuditPolicyState
{
    // AuditQuerySystemPolicy can return 0 for no auditing. For AuditSetSystemPolicy,
    // however, 0 means UNCHANGED; NONE (4) is required to explicitly disable auditing.
    public static uint Effective(uint flags) => flags switch
    {
        0 or 4 => 0,
        1 or 2 or 3 => flags,
        _ => throw new InvalidDataException($"Unsupported system audit flags: 0x{flags:X}. Recovery record preserved.")
    };
    public static uint IncludeFailure(uint flags) => Effective(flags) | 2u;
    public static void ApplyAndVerify(uint savedFlags, Action<uint> write, Func<uint> read)
    {
        uint desired = Effective(savedFlags);
        write(desired == 0 ? 4u : desired);
        uint actual = Effective(read());
        if (actual != desired) throw new IOException($"Audit policy restoration/readback mismatch: expected success/failure flags {desired}, observed {actual}. Recovery record preserved.");
    }
}
