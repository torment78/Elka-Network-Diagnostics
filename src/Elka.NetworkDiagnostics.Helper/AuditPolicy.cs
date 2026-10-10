using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Elka.NetworkDiagnostics.Windows;

namespace Elka.NetworkDiagnostics.Helper;

internal static class AuditPolicy
{
    private static readonly Guid PacketDrop = new("0CCE9225-69AE-11D9-BED3-505054503030");
    [StructLayout(LayoutKind.Sequential)] private struct Policy { public Guid Subcategory; public uint Flags; public Guid Category; }
    [StructLayout(LayoutKind.Sequential)] private struct Luid { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)] private struct Privileges { public uint Count; public Luid Id; public uint Attributes; }
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.U1)] private static extern bool AuditQuerySystemPolicy(ref Guid guid, uint count, out IntPtr policy);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.U1)] private static extern bool AuditSetSystemPolicy(ref Policy policy, uint count);
    [DllImport("advapi32.dll")] private static extern void AuditFree(IntPtr buffer);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool LookupPrivilegeValue(string? system, string name, out Luid luid);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool AdjustTokenPrivileges(IntPtr token, bool all, ref Privileges privileges, uint length, IntPtr old, IntPtr result);
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    public static uint Get()
    {
        EnablePrivilege(); Guid guid = PacketDrop;
        if (!AuditQuerySystemPolicy(ref guid, 1, out var buffer)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try { return Marshal.PtrToStructure<Policy>(buffer).Flags; } finally { AuditFree(buffer); }
    }
    public static void Set(uint flags)
    {
        AuditPolicyState.ApplyAndVerify(flags, nativeFlags =>
        {
            EnablePrivilege(); var policy = new Policy { Subcategory = PacketDrop, Flags = nativeFlags };
            if (!AuditSetSystemPolicy(ref policy, 1)) throw new Win32Exception(Marshal.GetLastWin32Error());
        }, Get);
    }
    private static void EnablePrivilege()
    {
        if (!OpenProcessToken(GetCurrentProcess(), 0x20 | 0x8, out var token)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            if (!LookupPrivilegeValue(null, "SeSecurityPrivilege", out var luid)) throw new Win32Exception(Marshal.GetLastWin32Error());
            var state = new Privileges { Count = 1, Id = luid, Attributes = 2 };
            if (!AdjustTokenPrivileges(token, false, ref state, 0, IntPtr.Zero, IntPtr.Zero) || Marshal.GetLastWin32Error() != 0) throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        finally { CloseHandle(token); }
    }
}
