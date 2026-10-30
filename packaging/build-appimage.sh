
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ARCH="${ARCH:-x86_64}"
APPDIR="$ROOT/Redoubt.AppDir"
VENV="$ROOT/.build-venv"

# Verifica strumenti
for cmd in python appimagetool; do
    command -v "$cmd" >/dev/null || {
        echo "Missing dependency: $cmd"
        exit 1
    }
done

# Ambiente Python
python -m venv "$VENV"
. "$VENV/bin/activate"

python -m pip install --upgrade pip
python -m pip install -e . pyinstaller

# PyInstaller
rm -rf build dist "$APPDIR"

pyinstaller --clean --noconfirm \
    --name Redoubt \
    --console \
    --collect-all sqlcipher3 \
    --collect-all textual \
    launcher.py

# AppDir
mkdir -p "$APPDIR/usr/bin"
cp -a dist/Redoubt/. "$APPDIR/usr/bin/"

cp packaging/AppRun "$APPDIR/AppRun"
cp packaging/redoubt.desktop "$APPDIR/redoubt.desktop"
cp packaging/redoubt.png "$APPDIR/redoubt.png"

chmod +x "$APPDIR/AppRun"

# AppImage
mkdir -p "$ROOT/appimages"
ARCH="$ARCH" appimagetool "$APPDIR" "$ROOT/appimages/Redoubt-$VERSION-$ARCH.AppImage"

echo "Build completed: appimages/Redoubt-$VERSION-$ARCH.AppImage"
