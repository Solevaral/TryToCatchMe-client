#!/usr/bin/env bash
# Strip libraries from the AppImage that must come from the host system.
#
# linuxdeploy bundles Ubuntu 22.04's libwayland-*, but EGL/Mesa are always taken
# from the host. On newer distros (Arch, CachyOS, Fedora...) the host Mesa can't
# work with the old bundled libwayland -> "EGL_BAD_PARAMETER" and a white window.
set -euo pipefail

appimage="$(readlink -f "$1")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cd "$work"
"$appimage" --appimage-extract >/dev/null

rm -fv squashfs-root/usr/lib/libwayland-*.so*

tool="$work/appimagetool"
curl -fsSL -o "$tool" \
  https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage
chmod +x "$tool"

ARCH=x86_64 APPIMAGE_EXTRACT_AND_RUN=1 "$tool" --no-appstream squashfs-root "$work/out.AppImage"
mv -f "$work/out.AppImage" "$appimage"
chmod +x "$appimage"
echo "Fixed: $appimage"
