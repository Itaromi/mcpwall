#!/usr/bin/env bash
#
# Signs, notarises and packages mcpwall.app into a .dmg.
#
# ⚠️ THIS SCRIPT HAS NEVER BEEN RUN OR VERIFIED.
# It was written with no Apple developer account available: no signing identity
# on the development machine. The commands follow Apple's documentation but must
# be treated as untested until somebody has run them end to end.
#
# Requirements:
#   - a "Developer ID Application" in the keychain
#     (check with `security find-identity -v -p codesigning`)
#   - a registered notarytool profile:
#       xcrun notarytool store-credentials mcpwall \
#         --apple-id YOUR@ID --team-id YOURTEAM --password APP-SPECIFIC-PASSWORD
#
# Usage:
#   MCPWALL_IDENTITY="Developer ID Application: Name (TEAMID)" ./scripts/sign-app.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"
APP="$BUILD/mcpwall.app"
DMG="$BUILD/mcpwall.dmg"
NOTARY_PROFILE="${MCPWALL_NOTARY_PROFILE:-mcpwall}"

if [[ ! -d "$APP" ]]; then
    echo "error: $APP is missing. Run scripts/build-app.sh first." >&2
    exit 1
fi

if [[ -z "${MCPWALL_IDENTITY:-}" ]]; then
    echo "error: MCPWALL_IDENTITY is not set." >&2
    echo "Available identities:" >&2
    security find-identity -v -p codesigning >&2
    exit 1
fi

# --- Entitlements ----------------------------------------------------------
# The hardened runtime is required for notarisation. mcpwall starts a child
# process (the daemon) and reads configuration files in the home directory:
# those two exceptions are therefore necessary. We ask for no others.
ENTITLEMENTS="$BUILD/mcpwall.entitlements"
cat > "$ENTITLEMENTS" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-jit</key>                        <false/>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key> <false/>
    <key>com.apple.security.cs.disable-library-validation</key>       <false/>
</dict>
</plist>
PLIST

# --- Signing ---------------------------------------------------------------
# Inside out: the embedded binary first, the bundle second. Signing the bundle
# first would invalidate its signature the moment we touched its contents.
echo "==> signing the embedded core"
codesign --force --timestamp --options runtime \
    --entitlements "$ENTITLEMENTS" \
    --sign "$MCPWALL_IDENTITY" \
    "$APP/Contents/Resources/mcpwall"

echo "==> signing the bundle"
codesign --force --timestamp --options runtime \
    --entitlements "$ENTITLEMENTS" \
    --sign "$MCPWALL_IDENTITY" \
    "$APP"

codesign --verify --deep --strict --verbose=2 "$APP"

# --- DMG -------------------------------------------------------------------
echo "==> dmg"
STAGING="$BUILD/dmg"
rm -rf "$STAGING" "$DMG"
mkdir -p "$STAGING"
cp -R "$APP" "$STAGING/"
# The shortcut to /Applications: the user drags and drops, they do not go
# looking for where to install.
ln -s /Applications "$STAGING/Applications"

hdiutil create -volname "mcpwall" -srcfolder "$STAGING" -ov -format UDZO "$DMG"
codesign --force --timestamp --sign "$MCPWALL_IDENTITY" "$DMG"

# --- Notarisation ----------------------------------------------------------
# Without it, Gatekeeper refuses to open the app and the user has to go through
# right click → Open. That is exactly the kind of friction that makes onboarding
# fail.
echo "==> notarisation (may take several minutes)"
xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait

echo "==> stapling"
xcrun stapler staple "$DMG"
xcrun stapler validate "$DMG"

# Final check: what the user's machine will see.
echo "==> Gatekeeper check"
spctl --assess --type open --context context:primary-signature --verbose=2 "$DMG"

echo
echo "ready: $DMG"
