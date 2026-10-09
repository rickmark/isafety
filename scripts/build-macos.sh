#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
export MACOSX_DEPLOYMENT_TARGET=14.0
cargo build --locked --release -p isafety-core
swift build --package-path macos -c release
bin="$(swift build --package-path macos -c release --show-bin-path)"
app="$root/build/iSafety.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$bin/iSafety" "$app/Contents/MacOS/iSafety"
cp macos/Info.plist "$app/Contents/Info.plist"
./scripts/build-app-icon.sh
cp build/AppIcon.icns "$app/Contents/Resources/AppIcon.icns"
codesign --force --sign "${ISAFETY_SIGNING_IDENTITY:--}" --options runtime --entitlements macos/iSafety.entitlements "$app"
codesign --verify --strict "$app"
echo "Built $app"
