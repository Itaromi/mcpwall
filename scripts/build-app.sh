#!/usr/bin/env bash
#
# Assemble mcpwall.app à partir du binaire Rust et du binaire Swift.
#
# Pas de projet Xcode : le bundle est monté à la main. Ça se construit avec les
# seuls Command Line Tools, donc identiquement en CI et sur une machine de
# développement, sans dépendre d'une version d'Xcode installée.
#
# La signature et la notarisation sont dans sign-app.sh, séparées exprès :
# construire ne doit pas exiger un compte développeur.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"
APP="$BUILD/mcpwall.app"

VERSION="${MCPWALL_VERSION:-0.1.0}"
BUILD_ID="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo dev)"

echo "==> mcpwall $VERSION ($BUILD_ID)"

# --- Core Rust -------------------------------------------------------------
# Universel : une machine Intel doit pouvoir exécuter le même .dmg qu'un Apple
# Silicon. Un binaire par architecture puis `lipo`.
echo "==> core (universel)"
cd "$ROOT"
for target in aarch64-apple-darwin x86_64-apple-darwin; do
    if ! rustup target list --installed | grep -q "^$target$"; then
        echo "    cible $target absente, installation"
        rustup target add "$target"
    fi
    MCPWALL_BUILD="$BUILD_ID" cargo build --release --target "$target" -p mcpwall
done

mkdir -p "$BUILD"
lipo -create -output "$BUILD/mcpwall-core" \
    "$ROOT/target/aarch64-apple-darwin/release/mcpwall" \
    "$ROOT/target/x86_64-apple-darwin/release/mcpwall"

# --- App Swift -------------------------------------------------------------
# Le build multi-architecture de SwiftPM passe par `xcbuild`, donc par Xcode.
# Avec les seuls Command Line Tools on ne peut produire que l'architecture
# native. On dégrade au lieu d'échouer — mais bruyamment, parce qu'un .dmg
# livré depuis une telle machine ne tournera pas partout.
echo "==> app"
cd "$ROOT/app"

if swift build -c release --arch arm64 --arch x86_64 >/dev/null 2>&1; then
    SWIFT_BIN="$(swift build -c release --arch arm64 --arch x86_64 --show-bin-path)/mcpwall"
else
    echo
    echo "    ⚠️  build universel indisponible (Xcode requis, "
    echo "        Command Line Tools seuls détectés)."
    echo "        L'app sera compilée pour $(uname -m) uniquement."
    echo "        Ne publiez pas ce bundle : construisez-le sur une machine"
    echo "        disposant d'Xcode, ou en CI."
    echo
    swift build -c release
    SWIFT_BIN="$(swift build -c release --show-bin-path)/mcpwall"
fi

# --- Bundle ----------------------------------------------------------------
echo "==> bundle"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cp "$SWIFT_BIN" "$APP/Contents/MacOS/mcpwall"
# Le core vit dans Resources et c'est vers lui que pointe le lien symbolique
# ~/.mcpwall/bin/mcpwall créé au premier lancement. Les configurations MCP ne
# référencent jamais ce chemin directement : sinon déplacer l'app casserait
# tous les serveurs de l'utilisateur.
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

    <!-- Pas d'icône dans le Dock : mcpwall vit dans la barre de menus. -->
    <key>LSUIElement</key>                   <true/>

    <key>NSHighResolutionCapable</key>       <true/>

    <!-- Sparkle. Laissé vide tant qu'aucun flux n'est publié : une URL morte
         provoquerait une erreur de mise à jour à chaque lancement. -->
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
echo "Non signé. Voir scripts/sign-app.sh pour signer et notariser."
