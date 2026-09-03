# Dev launcher: puts MSYS2 MinGW on PATH (required by the GNU Rust toolchain) and
# starts the Tauri dev app (Vite + Rust hot-reload).
$env:Path = "C:\msys64\mingw64\bin;" + $env:Path
Set-Location "$PSScriptRoot\.."
npm run tauri dev
