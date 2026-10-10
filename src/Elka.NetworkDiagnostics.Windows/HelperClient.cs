using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using Elka.NetworkDiagnostics.Core;

namespace Elka.NetworkDiagnostics.Windows;

public static class HelperClient
{
    public static async Task Run(HelperRequest request, Func<HelperMessage, Task> onMessage)
    {
        string helper = Path.Combine(AppContext.BaseDirectory, "Elka.NetworkDiagnostics.Helper.exe");
        if (!File.Exists(helper)) throw new FileNotFoundException("The elevated helper is missing. Use the complete portable folder.", helper);
        string pipeName = "ElkaNetworkDiagnostics-" + Guid.NewGuid().ToString("N");
        string nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        using var pipe = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        var info = new ProcessStartInfo(helper) { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
        info.ArgumentList.Add(pipeName); info.ArgumentList.Add(nonce);
        using var process = Process.Start(info) ?? throw new IOException("Elevated helper could not start.");
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(request.Action == "CreateRestorePoint" ? 15 : 4));
        await pipe.WaitForConnectionAsync(deadline.Token);
        using var reader = new StreamReader(pipe, leaveOpen: true);
        using var writer = new StreamWriter(pipe, leaveOpen: true) { AutoFlush = true };
        if (await reader.ReadLineAsync(deadline.Token) != nonce) throw new InvalidDataException("Helper authentication failed.");
        await writer.WriteLineAsync(Json.Write(request));
        bool completed = false;
        while (await reader.ReadLineAsync(deadline.Token) is string line)
        {
            if (line.Length > 150_000) throw new InvalidDataException("Helper response exceeds the limit.");
            var message = Json.Read<HelperMessage>(line); await onMessage(message);
            if (message.Kind == "error") throw new InvalidOperationException(message.Text);
            if (message.Kind is "done" or "cancelled" or "inconclusive") { completed = true; break; }
        }
        if (!completed) throw new IOException("Helper connection ended early. Check pending recovery before another repair.");
    }
}
