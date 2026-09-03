# Release build: MinGW on PATH, then bundle the Windows installer via Tauri.
$env:Path = "C:\msys64\mingw64\bin;" + $env:Path
Set-Location "$PSScriptRoot\.."
npm run tauri build
