#!/usr/bin/env bash
#
# Assembles mcpwall.app from the Rust binary and the Swift binary.
#
# No Xcode project: the bundle is put together by hand. It builds with the
# Command Line Tools alone, so identically in CI and on a development machine,
# without depending on an installed Xcode version.
#
# Signing and notarisation live in sign-app.sh, deliberately separate: building
# must not require a developer account.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"
APP="$BUILD/mcpwall.app"

VERSION="${MCPWALL_VERSION:-0.1.0}"
BUILD_ID="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo dev)"

echo "==> mcpwall $VERSION ($BUILD_ID)"

# --- Rust core -------------------------------------------------------------
# Universal: an Intel machine must be able to run the same .dmg as an Apple
# Silicon one. One binary per architecture, then `lipo`.
echo "==> core (universal)"
cd "$ROOT"
for target in aarch64-apple-darwin x86_64-apple-darwin; do
    if ! rustup target list --installed | grep -q "^$target$"; then
        echo "    target $target missing, installing"
        rustup target add "$target"
    fi
    MCPWALL_BUILD="$BUILD_ID" cargo build --release --target "$target" -p mcpwall
done

mkdir -p "$BUILD"
lipo -create -output "$BUILD/mcpwall-core" \
    "$ROOT/target/aarch64-apple-darwin/release/mcpwall" \
    "$ROOT/target/x86_64-apple-darwin/release/mcpwall"

# --- Swift app -------------------------------------------------------------
# SwiftPM's multi-architecture build goes through `xcbuild`, and therefore
# through Xcode. With the Command Line Tools alone we can only produce the
# native architecture. We degrade instead of failing — but loudly, because a
# .dmg shipped from such a machine will not run everywhere.
echo "==> app"
cd "$ROOT/app"

if swift build -c release --arch arm64 --arch x86_64 >/dev/null 2>&1; then
    SWIFT_BIN="$(swift build -c release --arch arm64 --arch x86_64 --show-bin-path)/mcpwall"
else
    echo
    echo "    ⚠️  universal build unavailable (Xcode required,"
    echo "        only Command Line Tools detected)."
    echo "        The app will be compiled for $(uname -m) only."
    echo "        Do not publish this bundle: build it on a machine that"
    echo "        has Xcode, or in CI."
    echo
    swift build -c release
    SWIFT_BIN="$(swift build -c release --show-bin-path)/mcpwall"
fi

# --- Bundle ----------------------------------------------------------------
echo "==> bundle"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cp "$SWIFT_BIN" "$APP/Contents/MacOS/mcpwall"
# The core lives in Resources, and it is what the ~/.mcpwall/bin/mcpwall
# symlink created on first launch points at. MCP configurations never reference
# this path directly: otherwise moving the app would break every one of the
# user's servers.
cp "$BUILD/mcpwall-core" "$APP/Contents/Resources/mcpwall"
chmod +x "$APP/Contents/MacOS/mcpwall" "$APP/Contents/Resources/mcpwall"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>                  <string>mcpwall</string>
    <key>CFBundleDisplayName</key>           <string>mcpwall</string>
    <key>CFBundleIdentifier</key>            <string>dev.mcpwall.app</string>
    <key>CFBundleExecutable</key>            <string>mcpwall</string>
    <key>CFBundlePackageType</key>           <string>APPL</string>
    <key>CFBundleShortVersionString</key>    <string>$VERSION</string>
    <key>CFBundleVersion</key>               <string>$VERSION</string>
    <key>LSMinimumSystemVersion</key>        <string>14.0</string>

    <!-- No Dock icon: mcpwall lives in the menu bar. -->
    <key>LSUIElement</key>                   <true/>

    <key>NSHighResolutionCapable</key>       <true/>

    <!-- Sparkle. Left empty for as long as no feed is published: a dead URL
         would raise an update error on every launch. -->
    <key>SUFeedURL</key>                     <string></string>
    <key>SUEnableAutomaticChecks</key>       <false/>
</dict>
</plist>
PLIST

cat > "$APP/Contents/PkgInfo" <<< "APPL????"

echo "==> $APP"
echo "    core  $(lipo -archs "$APP/Contents/Resources/mcpwall")"
echo "    app   $(lipo -archs "$APP/Contents/MacOS/mcpwall")"
echo
echo "Unsigned. See scripts/sign-app.sh to sign and notarise."
