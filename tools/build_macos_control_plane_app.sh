#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_NAME="Litebike Operator Bar"
EXECUTABLE_NAME="LitebikeControlPlane"
MACOS_DIR="$REPO_ROOT/macos/LitebikeControlPlane"
BUILD_ROOT="$REPO_ROOT/.artifacts/macos"
APP_BUNDLE="$BUILD_ROOT/$APP_NAME.app"
INSTALL_APP="/Applications/$APP_NAME.app"
INSTALL_APP_FLAG=0

if [[ "${1:-}" == "--install" ]]; then
    INSTALL_APP_FLAG=1
fi

rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"

export REPO_ROOT APP_BUNDLE

python3 <<'PY'
import os
from pathlib import Path

repo_root = os.environ["REPO_ROOT"]
app_bundle = Path(os.environ["APP_BUNDLE"])
template = Path(repo_root) / "macos" / "LitebikeControlPlane" / "Info.plist"
dest = app_bundle / "Contents" / "Info.plist"
dest.write_text(template.read_text().replace("__WORKSPACE_ROOT__", repo_root))
PY

swiftc \
    -O \
    -framework AppKit \
    "$MACOS_DIR/Sources/main.swift" \
    -o "$APP_BUNDLE/Contents/MacOS/$EXECUTABLE_NAME"

cp "$REPO_ROOT/tools/litebike_operator_actions.sh" "$APP_BUNDLE/Contents/Resources/litebike_operator_actions.sh"
cp "$MACOS_DIR/Resources/litebike-medallion.svg" "$APP_BUNDLE/Contents/Resources/litebike-medallion.svg"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

APP_ICONSET="$tmpdir/AppIcon.iconset"
mkdir -p "$APP_ICONSET"
sips -s format png "$MACOS_DIR/Resources/litebike-medallion.svg" --out "$tmpdir/app-icon-1024.png" >/dev/null

for size in 16 32 128 256 512; do
    sips -z "$size" "$size" "$tmpdir/app-icon-1024.png" --out "$APP_ICONSET/icon_${size}x${size}.png" >/dev/null
done

for size in 16 32 128 256 512; do
    retina_size=$((size * 2))
    sips -z "$retina_size" "$retina_size" "$tmpdir/app-icon-1024.png" --out "$APP_ICONSET/icon_${size}x${size}@2x.png" >/dev/null
done

iconutil -c icns "$APP_ICONSET" -o "$APP_BUNDLE/Contents/Resources/AppIcon.icns"
sips -s format png "$MACOS_DIR/Resources/status-template.svg" --out "$APP_BUNDLE/Contents/Resources/StatusIconTemplate.png" >/dev/null

chmod +x "$APP_BUNDLE/Contents/MacOS/$EXECUTABLE_NAME"
chmod +x "$APP_BUNDLE/Contents/Resources/litebike_operator_actions.sh"

if [[ -n "${DEVELOPER_ID_APPLICATION:-}" ]]; then
    echo "Signing app bundle..."
    codesign --deep --force --verify \
        --options runtime \
        --sign "$DEVELOPER_ID_APPLICATION" \
        "$APP_BUNDLE"
fi

if [[ -n "${DEVELOPER_ID_INSTALLER:-}" ]]; then
    PKG_PATH="$BUILD_ROOT/$APP_NAME.pkg"
    echo "Building signed installer package..."
    pkgbuild --install-location "/Applications" \
        --component "$APP_BUNDLE" \
        --sign "$DEVELOPER_ID_INSTALLER" \
        "$PKG_PATH"
    echo "Packaged installer at $PKG_PATH"
fi

if [[ "$INSTALL_APP_FLAG" -eq 1 ]]; then
    ditto "$APP_BUNDLE" "$INSTALL_APP"
    echo "Installed app bundle at $INSTALL_APP"
fi

echo "Built app bundle at $APP_BUNDLE"
