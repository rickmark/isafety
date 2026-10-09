#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
source_image="$root/assets/brand/isafety-fold-icon-dimensional.png"
iconset="$root/build/AppIcon.iconset"
mkdir -p "$iconset"

# Include standard and Retina representations for Finder and the Dock.
for size in 16 32 128 256 512; do
    sips -z "$size" "$size" "$source_image" --out "$iconset/icon_${size}x${size}.png" >/dev/null
    retina_size=$((size * 2))
    sips -z "$retina_size" "$retina_size" "$source_image" --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$root/build/AppIcon.icns"
