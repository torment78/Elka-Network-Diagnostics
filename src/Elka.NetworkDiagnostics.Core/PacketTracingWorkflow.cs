namespace Elka.NetworkDiagnostics.Core;

public static class PacketTracingWorkflow
{
    // Each collector is independent. A failure in PktMon must still reach Npcap setup/capture.
    public static async Task Run(Func<string, Task> capture, Func<Task<bool>> ensureNpcap,
        Action<string, Exception> failed, CancellationToken ct)
    {
        foreach (string action in new[] { "WfpAudit", "PacketCapture", "NpcapCapture" })
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                if (action == "NpcapCapture" && !await ensureNpcap()) continue;
                ct.ThrowIfCancellationRequested();
                await capture(action);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception e) { failed(action, e); }
        }
    }
}
