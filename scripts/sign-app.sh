#!/usr/bin/env bash
#
# Signe, notarise et empaquette mcpwall.app en .dmg.
#
# ⚠️ CE SCRIPT N'A PAS PU ÊTRE EXÉCUTÉ NI VÉRIFIÉ.
# Il a été écrit sans compte développeur Apple disponible : aucune identité de
# signature sur la machine de développement. Les commandes suivent la
# documentation d'Apple mais doivent être considérées comme non testées tant
# que quelqu'un ne les aura pas fait tourner de bout en bout.
#
# Prérequis :
#   - un « Developer ID Application » dans le trousseau
#     (vérifier avec `security find-identity -v -p codesigning`)
#   - un profil notarytool enregistré :
#       xcrun notarytool store-credentials mcpwall \
#         --apple-id VOTRE@ID --team-id VOTRETEAM --password MOT-DE-PASSE-APP
#
# Usage :
#   MCPWALL_IDENTITY="Developer ID Application: Nom (TEAMID)" ./scripts/sign-app.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"
APP="$BUILD/mcpwall.app"
DMG="$BUILD/mcpwall.dmg"
NOTARY_PROFILE="${MCPWALL_NOTARY_PROFILE:-mcpwall}"

if [[ ! -d "$APP" ]]; then
    echo "erreur : $APP absent. Lancez d'abord scripts/build-app.sh." >&2
    exit 1
fi

if [[ -z "${MCPWALL_IDENTITY:-}" ]]; then
    echo "erreur : MCPWALL_IDENTITY non défini." >&2
    echo "Identités disponibles :" >&2
    security find-identity -v -p codesigning >&2
    exit 1
fi

# --- Entitlements ----------------------------------------------------------
# Le durcissement du runtime est exigé pour la notarisation. mcpwall lance un
# processus enfant (le daemon) et lit des fichiers de configuration dans le
# home : ces deux exceptions sont donc nécessaires. On n'en demande pas d'autre.
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

# --- Signature -------------------------------------------------------------
# De l'intérieur vers l'extérieur : le binaire embarqué d'abord, le bundle
# ensuite. Signer le bundle en premier invaliderait sa signature dès qu'on
# toucherait à son contenu.
echo "==> signature du core embarqué"
codesign --force --timestamp --options runtime \
    --entitlements "$ENTITLEMENTS" \
    --sign "$MCPWALL_IDENTITY" \
    "$APP/Contents/Resources/mcpwall"

echo "==> signature du bundle"
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
# Le raccourci vers /Applications : l'utilisateur glisse-dépose, il ne cherche
# pas où installer.
ln -s /Applications "$STAGING/Applications"

hdiutil create -volname "mcpwall" -srcfolder "$STAGING" -ov -format UDZO "$DMG"
codesign --force --timestamp --sign "$MCPWALL_IDENTITY" "$DMG"

# --- Notarisation ----------------------------------------------------------
# Sans elle, Gatekeeper refuse l'ouverture et l'utilisateur doit passer par un
# clic droit → Ouvrir. C'est exactement le genre de friction qui fait échouer
# l'onboarding.
echo "==> notarisation (peut prendre plusieurs minutes)"
xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait

echo "==> agrafage"
xcrun stapler staple "$DMG"
xcrun stapler validate "$DMG"

# Contrôle final : ce que verra la machine de l'utilisateur.
echo "==> vérification Gatekeeper"
spctl --assess --type open --context context:primary-signature --verbose=2 "$DMG"

echo
echo "prêt : $DMG"
