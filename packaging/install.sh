#!/bin/sh
set -eu

APP_DIR="$HOME/.redoubt"
APPLICATIONS_DIR="$HOME/.local/share/applications"

APP_URL="https://github.com/FreyFlyy/Redoubt/releases/download/2.1.0/Redoubt-2.1.0-x86_64.AppImage"
ICON_URL="https://raw.githubusercontent.com/FreyFlyy/Redoubt/main/packaging/redoubt.png"

APP_FILE="$APP_DIR/Redoubt-2.1.0-x86_64.AppImage"
ICON_FILE="$APP_DIR/redoubt.png"
DESKTOP_FILE="$APPLICATIONS_DIR/Redoubt.desktop"

echo "Installing Redoubt..."

# Create directories
mkdir -p "$APP_DIR"
mkdir -p "$APPLICATIONS_DIR"

# Download AppImage
echo "Downloading AppImage..."
curl -fL --progress-bar "$APP_URL" -o "$APP_FILE"

# Download icon
echo "Downloading icon..."
curl -fL --progress-bar "$ICON_URL" -o "$ICON_FILE"

# Make AppImage executable
chmod +x "$APP_FILE"

# Create desktop entry
echo "Creating desktop entry..."

cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Redoubt
Comment=A peer-to-peer messaging app with end-to-end message encryption and hardened client runtime
Exec=$APP_FILE
Icon=$ICON_FILE
Terminal=true
Categories=Network;
StartupNotify=false
EOF

# Refresh application database if available
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPLICATIONS_DIR" 2>/dev/null || true
fi

echo ""
echo "Redoubt installed successfully!"
echo "Launcher: $DESKTOP_FILE"
echo "AppImage: $APP_FILE"
