#!/usr/bin/env bash
set -euo pipefail

arch=${1:?Expected arm64 or x64}
output=${2:?Expected output directory}
root=$(cd "$(dirname "$0")/.." && pwd)
project="$root/v2rayN/v2rayN.Desktop/v2rayN.Desktop.csproj"
version=$(dotnet msbuild "$project" -nologo -getProperty:VaKoLinkVersion)
[[ "$version" =~ ^[0-9]+\.[0-9]+$ ]]
[[ $(dotnet --version) == 10.0.114 ]]
case "$arch" in
  arm64)
    hardware=arm64
    xray=Xray-macos-arm64-v8a.zip
    xray_hash=0a05dca3bd311b0bc5a89c7ce56350cab1e829e131e4b2bcd48eb304fac07e9a
    sing=sing-box-1.14.4-darwin-arm64
    sing_hash=0d8c7f5ed5d587b0f1a5e9772a708ec3bfa4ac4c9329604b01d8d9c2ba406838
    mihomo=mihomo-darwin-arm64-v1.19.33.gz
    mihomo_hash=060b64b0f2c9a310831db0fe4adb2878de67bfa606c311813c1f13966aa504b6 ;;
  x64)
    hardware=x86_64
    xray=Xray-macos-64.zip
    xray_hash=37c60b63c77ef5edcfb46a0d70349f7d96e0c132e6a356ead4fd20aeeacc5c75
    sing=sing-box-1.14.4-darwin-amd64
    sing_hash=eae86b9b033bba50b7c44ab719e4bfac0aca05efd28483390ed3aa510f32db25
    mihomo=mihomo-darwin-amd64-v1-v1.19.33.gz
    mihomo_hash=61f979d6aae3deffe4e3895161349c3d9189149eef88c5aceb7c6d4a7270a78d ;;
  *) echo "Unsupported macOS architecture" >&2; exit 2 ;;
esac
[[ $(uname -m) == "$hardware" ]]
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
stage="$work/package"
app="$stage/VaKoLink.app"
macos="$app/Contents/MacOS"
resources="$app/Contents/Resources"
mkdir -p "$macos" "$resources" "$output"

download() {
  local url=$1 destination=$2 digest=$3
  curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --retry 3 --max-time 180 --output "$destination" "$url"
  printf '%s  %s\n' "$digest" "$destination" | shasum -a 256 -c -
}

dotnet publish "$project" -c Release -r "osx-$arch" --self-contained true \
  -p:DebugType=None -p:DebugSymbols=false "-p:PathMap=$root=/_/VaKoLink-Client" -o "$macos"
bin="$macos/bin"
mkdir -p "$bin/xray" "$bin/sing_box" "$bin/mihomo" "$stage/sources"
download "https://github.com/XTLS/Xray-core/releases/download/v26.10.31/$xray" "$work/xray.zip" "$xray_hash"
unzip -q "$work/xray.zip" xray geoip.dat geosite.dat -d "$bin/xray"
download "https://github.com/SagerNet/sing-box/releases/download/v1.14.4/$sing.tar.gz" "$work/sing.tar.gz" "$sing_hash"
tar -xOf "$work/sing.tar.gz" "$sing/sing-box" > "$bin/sing_box/sing-box"
download "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/$mihomo" "$work/mihomo.gz" "$mihomo_hash"
gzip -dc "$work/mihomo.gz" > "$bin/mihomo/mihomo"
chmod +x "$bin/xray/xray" "$bin/sing_box/sing-box" "$bin/mihomo/mihomo"
cp "$root/v2rayN/v2rayN.Desktop/v2rayN.icns" "$resources/AppIcon.icns"
cp "$root/LICENSE" "$stage/LICENSE.txt"
cp "$root/tools/VaKoLink-macOS.txt" "$stage/Readme.txt"
git -C "$root" rev-parse HEAD > "$stage/SourceCommit.txt"
git -C "$root" archive --format=zip -o "$stage/sources/VaKoLink-source.zip" HEAD
git -C "$root/v2rayN/GlobalHotKeys" archive --format=zip --prefix=v2rayN/GlobalHotKeys/ \
  -o "$stage/sources/GlobalHotKeys-source.zip" HEAD
printf '%s\n' 'Xray 26.10.31 https://github.com/XTLS/Xray-core/tree/v26.10.31' \
  'sing-box 1.14.4 https://github.com/SagerNet/sing-box/tree/v1.14.4' \
  'mihomo 1.19.33 https://github.com/MetaCubeX/mihomo/tree/v1.19.33' > "$stage/sources/ComponentSources.txt"
unzip -p "$work/xray.zip" LICENSE > "$stage/sources/Xray-LICENSE.txt"
tar -xOf "$work/sing.tar.gz" "$sing/LICENSE" > "$stage/sources/sing-box-LICENSE.txt"
curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --max-time 40 'https://raw.githubusercontent.com/MetaCubeX/mihomo/v1.19.33/LICENSE' > "$stage/sources/mihomo-LICENSE.txt"

cat > "$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.vakolink.client</string>
<key>CFBundleName</key><string>VaKoLink</string>
<key>CFBundleDisplayName</key><string>VaKoLink</string>
<key>CFBundleExecutable</key><string>VaKoLink</string>
<key>CFBundleShortVersionString</key><string>$version</string>
<key>CFBundleVersion</key><string>$version</string>
<key>CFBundleIconFile</key><string>AppIcon.icns</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSMinimumSystemVersion</key><string>13.6</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
EOF
plutil -lint "$app/Contents/Info.plist"
for executable in "$macos/VaKoLink" "$bin/xray/xray" "$bin/sing_box/sing-box" "$bin/mihomo/mihomo"; do
  lipo -verify_arch "$hardware" "$executable"
done
while IFS= read -r -d '' file; do
  if file -b "$file" | grep -q 'Mach-O'; then codesign --force --sign - "$file"; fi
done < <(find "$macos" -type f -print0)
codesign --force --sign - "$app"
name="VaKoLink-v$version-macos-$arch.zip"
ditto -c -k --sequesterRsrc "$stage" "$output/$name"
mkdir "$work/verified"
ditto -x -k "$output/$name" "$work/verified"
verified="$work/verified/VaKoLink.app"
codesign --verify --strict --deep "$verified"
"$verified/Contents/MacOS/bin/xray/xray" version | grep '26.10.31'
"$verified/Contents/MacOS/bin/sing_box/sing-box" version | grep '1.14.4'
"$verified/Contents/MacOS/bin/mihomo/mihomo" -v | grep '1.19.33'
log="$work/launch.log"
"$verified/Contents/MacOS/VaKoLink" --vakolink-ci-smoke > "$log" 2>&1 &
pid=$!
for ((i=0; i<30; i++)); do
  if ! kill -0 "$pid" 2>/dev/null; then break; fi
  sleep 1
done
if kill -0 "$pid" 2>/dev/null; then
  kill "$pid"
  cat "$log"
  exit 1
fi
wait "$pid"
grep -F "VaKoLink v$version" "$log"
(cd "$output" && shasum -a 256 "$name" > "$name.sha256")
