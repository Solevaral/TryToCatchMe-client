# Downloads the sing-box core and Wintun driver into src-tauri/binaries/.
# These are gitignored (large binaries); run this once after cloning.
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$bin = Join-Path $root "src-tauri\binaries"
New-Item -ItemType Directory -Force -Path $bin | Out-Null
$tmp = Join-Path $env:TEMP "ttcm-fetch"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

$singboxVersion = "1.14.0"
$wintunVersion = "0.14.1"

Write-Host "Downloading sing-box $singboxVersion ..."
$sbUrl = "https://github.com/SagerNet/sing-box/releases/download/v$singboxVersion/sing-box-$singboxVersion-windows-amd64.zip"
$sbZip = Join-Path $tmp "singbox.zip"
Invoke-WebRequest -Uri $sbUrl -OutFile $sbZip
Expand-Archive -Path $sbZip -DestinationPath (Join-Path $tmp "singbox") -Force
$sbExe = Get-ChildItem -Path (Join-Path $tmp "singbox") -Recurse -Filter "sing-box.exe" | Select-Object -First 1
Copy-Item $sbExe.FullName (Join-Path $bin "sing-box.exe") -Force

Write-Host "Downloading Wintun $wintunVersion ..."
$wtUrl = "https://www.wintun.net/builds/wintun-$wintunVersion.zip"
$wtZip = Join-Path $tmp "wintun.zip"
Invoke-WebRequest -Uri $wtUrl -OutFile $wtZip
Expand-Archive -Path $wtZip -DestinationPath (Join-Path $tmp "wintun") -Force
$wtDll = Get-ChildItem -Path (Join-Path $tmp "wintun") -Recurse -Filter "wintun.dll" | Where-Object { $_.FullName -match 'amd64' } | Select-Object -First 1
Copy-Item $wtDll.FullName (Join-Path $bin "wintun.dll") -Force

Remove-Item -Recurse -Force $tmp
Write-Host "Done. Binaries in $bin :"
Get-ChildItem $bin | Select-Object Name, Length
