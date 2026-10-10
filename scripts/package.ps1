param([string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$artifactRoot = Join-Path $projectRoot 'artifacts'
$version = ([xml](Get-Content -LiteralPath (Join-Path $projectRoot 'Directory.Build.props') -Raw)).Project.PropertyGroup.Version
$packageDir = Join-Path $artifactRoot "Elka-Network-Diagnostics-$version-win-x64-$stamp"
New-Item -ItemType Directory -Path $packageDir -Force | Out-Null
dotnet publish (Join-Path $projectRoot 'src\Elka.NetworkDiagnostics.App\Elka.NetworkDiagnostics.App.csproj') -c $Configuration -r win-x64 --self-contained true -o $packageDir -p:PublishSingleFile=false
if ($LASTEXITCODE -ne 0) { throw 'App publish failed.' }
dotnet publish (Join-Path $projectRoot 'src\Elka.NetworkDiagnostics.Helper\Elka.NetworkDiagnostics.Helper.csproj') -c $Configuration -r win-x64 --self-contained true -o $packageDir -p:PublishSingleFile=false
if ($LASTEXITCODE -ne 0) { throw 'Helper publish failed.' }
Copy-Item -LiteralPath (Join-Path $projectRoot 'README.md') -Destination (Join-Path $packageDir 'README.md')
Copy-Item -LiteralPath (Join-Path $projectRoot 'SETUP.md') -Destination (Join-Path $packageDir 'SETUP.md')
Copy-Item -LiteralPath (Join-Path $projectRoot 'SETUP.md') -Destination (Join-Path $packageDir 'START-HERE.md')
Copy-Item -LiteralPath (Join-Path $projectRoot 'START-HERE.html') -Destination (Join-Path $packageDir 'START-HERE.html')
New-Item -ItemType Directory -Path (Join-Path $packageDir 'docs\images') -Force | Out-Null
Get-ChildItem -LiteralPath (Join-Path $projectRoot 'docs\images') -Filter '*.png' -File | Copy-Item -Destination (Join-Path $packageDir 'docs\images')
Copy-Item -LiteralPath (Join-Path $projectRoot 'third-party') -Destination (Join-Path $packageDir 'third-party') -Recurse
@'
START THE APPLICATION: Elka.NetworkDiagnostics.exe

Extract the entire folder on BOTH PCs. The Helper executable opens automatically when needed; it is not the main app.

1. Choose each PC's LAN adapter and enter the OTHER PC's IPv4 address.
2. Put the SAME pairing code and matching ports on both PCs. Start both endpoints and wait for Paired.
3. Click Check both PCs on ONE machine only. Both apps join the shared test.
4. Follow the result. On the PC to inspect first, open Diagnostics and click Run all checks.
5. STAY AT THAT PC to answer Windows permission and setup prompts. Keep the other app open, paired and idle.
6. Wait for the final recommendations and available run buttons, then run all checks on the other PC.

NEVER RUN ALL CHECKS ON BOTH PCs AT THE SAME TIME. Do not start individual tests on the other PC during a scan.
Wait for the scan to finish, not for every result to turn green. Warnings can remain after completion.

OPEN START-HERE.html IN YOUR BROWSER for the illustrated guide. The Markdown copy is also provided as SETUP.md and START-HERE.md.
'@ | Set-Content -LiteralPath (Join-Path $packageDir 'OPEN-ELKA-NETWORK-DIAGNOSTICS.txt') -Encoding utf8
$archive = $packageDir + '.zip'
Compress-Archive -LiteralPath $packageDir -DestinationPath $archive -CompressionLevel Optimal
$hash = Get-FileHash -LiteralPath $archive -Algorithm SHA256
"$($hash.Hash)  $([IO.Path]::GetFileName($archive))" | Set-Content -LiteralPath ($archive + '.sha256') -Encoding ascii
Get-Item -LiteralPath $archive | Select-Object FullName,Length
$hash | Select-Object Hash
