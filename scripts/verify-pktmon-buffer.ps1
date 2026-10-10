param([Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$transcriptPath = Join-Path $OutputDirectory 'buffer-verification.txt'
Start-Transcript -LiteralPath $transcriptPath | Out-Null
try {
    foreach ($captureSize in @(16, 64)) {
        $capturePath = Join-Path $OutputDirectory "buffer-$captureSize.etl"
        & "$env:SystemRoot\System32\pktmon.exe" start --capture --comp all --type all --flags 0x032 --pkt-size 128 --log-mode circular --file-size $captureSize --file-name $capturePath
        if ($LASTEXITCODE -ne 0) { throw 'Capture could not start. No existing session will be stopped.' }
        try {
            & "$env:SystemRoot\System32\pktmon.exe" status
            $receiver = [Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 0))
            $sender = [Net.Sockets.UdpClient]::new()
            try {
                $receiver.Client.ReceiveTimeout = 2000
                $target = $receiver.Client.LocalEndPoint
                $payload = [Text.Encoding]::ASCII.GetBytes('Elka PktMon buffer verification')
                for ($packetIndex = 0; $packetIndex -lt 20; $packetIndex++) {
                    [void]$sender.Send($payload, $payload.Length, $target)
                    $source = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
                    [void]$receiver.Receive([ref]$source)
                }
                'Verified 20 loopback UDP deliveries.'
            } finally { $sender.Dispose(); $receiver.Dispose() }
            Start-Sleep -Seconds 2
            & "$env:SystemRoot\System32\pktmon.exe" counters
        } finally {
            & "$env:SystemRoot\System32\pktmon.exe" stop
            if ($LASTEXITCODE -ne 0) { throw 'Owned capture failed to stop; verification aborted.' }
        }
        & "$env:SystemRoot\System32\pktmon.exe" etl2txt $capturePath --stats
        & "$env:SystemRoot\System32\pktmon.exe" etl2txt $capturePath --out (Join-Path $OutputDirectory "buffer-$captureSize.txt") --hex
    }
    'Verification finished.'
} catch { $_ | Out-String | Write-Output }
finally { Stop-Transcript | Out-Null }
