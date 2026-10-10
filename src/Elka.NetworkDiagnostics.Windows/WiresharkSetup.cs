using System.Net.Http;
using System.Security.Cryptography;

namespace Elka.NetworkDiagnostics.Windows;

public static class WiresharkSetup
{
    public const string Version = "4.6.9";
    public const string DownloadUrl = "https://www.wireshark.org/download/win64/Wireshark-4.6.9-x64.exe";
    // Official SIGNATURES-4.6.9.txt. A changed download is never run automatically.
    public const string Sha256 = "BF9B5CE8A89F244C376A9B1A946276EAA06463DDE3E33069A34D7F102F5878CF";
    public const long FileSize = 97_931_232;

    public static async Task<string> Download(string root, Action<string> progress, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromMinutes(10)); ct = deadline.Token;
        string directory = Path.Combine(root, "installers"); System.IO.Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, $"Wireshark-{Version}-x64-{Guid.NewGuid():N}.exe");
        try
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
            using var response = await client.GetAsync(DownloadUrl, HttpCompletionOption.ResponseHeadersRead, ct);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength is long size && size != FileSize) throw new InvalidDataException("Unexpected installer size. Download was not accepted.");
            await using (var input = await response.Content.ReadAsStreamAsync(ct))
            await using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, true))
            {
                byte[] buffer = new byte[81920]; long total = 0; int count, lastPercent = -1;
                while ((count = await input.ReadAsync(buffer, ct)) > 0)
                {
                    total += count;
                    if (total > FileSize) throw new InvalidDataException("Installer download exceeded its expected size.");
                    await output.WriteAsync(buffer.AsMemory(0, count), ct);
                    int percent = (int)(total * 100 / FileSize);
                    if (percent != lastPercent) { lastPercent = percent; progress($"Downloading Wireshark: {percent}%"); }
                }
            }
            progress("Verifying the official Wireshark installer…");
            await Verify(path, ct);
            return path;
        }
        catch { if (File.Exists(path)) File.Delete(path); throw; }
    }

    public static async Task Verify(string path, CancellationToken ct)
    {
        await using (var stream = File.OpenRead(path))
            if (stream.Length != FileSize || !Convert.ToHexString(await SHA256.HashDataAsync(stream, ct)).Equals(Sha256, StringComparison.Ordinal))
                throw new InvalidDataException("Wireshark installer hash did not match the official release. Installation was blocked.");
        var signature = await Commands.PowerShell("Import-Module (Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1') -Force -ErrorAction Stop; $s = Get-AuthenticodeSignature -LiteralPath " + Commands.Quote(path) +
            "; if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch '(^|, )O=Wireshark Foundation(,|$)') { throw 'Wireshark publisher signature could not be verified.' }; 'Verified Wireshark Foundation signature'", ct);
        if (signature.ExitCode != 0) throw new InvalidDataException("Installer signature verification failed.\n" + signature.Combined);
    }
}
