
#!/bin/sh
set -eu

APP_DIR="$HOME/.redoubt"
APPLICATIONS_DIR="$HOME/.local/share/applications"
FONTS_DIR="$HOME/.local/share/fonts/MesloLGS"

APP_URL="https://github.com/FreyFlyy/Redoubt/releases/download/2.1.0/Redoubt-2.1.0-x86_64.AppImage"
ICON_URL="https://raw.githubusercontent.com/FreyFlyy/Redoubt/main/packaging/redoubt.png"
FONT_BASE_URL="https://raw.githubusercontent.com/FreyFlyy/Redoubt/main/packaging/fonts"

APP_FILE="$APP_DIR/Redoubt-2.1.0-x86_64.AppImage"
ICON_FILE="$APP_DIR/redoubt.png"
DESKTOP_FILE="$APPLICATIONS_DIR/Redoubt.desktop"

FONT_FILES="
MesloLGS NF Regular.ttf
MesloLGS NF Bold.ttf
MesloLGS NF Italic.ttf
MesloLGS NF Bold Italic.ttf
"

echo "Installing Redoubt..."

# Create directories
mkdir -p "$APP_DIR"
mkdir -p "$APPLICATIONS_DIR"
mkdir -p "$FONTS_DIR"

# Download AppImage
echo "Downloading AppImage..."
curl -fL --progress-bar "$APP_URL" -o "$APP_FILE"

# Download icon
echo "Downloading icon..."
curl -fL --progress-bar "$ICON_URL" -o "$ICON_FILE"

# Make AppImage executable
chmod +x "$APP_FILE"

# Install MesloLGS Nerd Font
echo "Installing MesloLGS Nerd Font..."

printf '%s\n' "$FONT_FILES" | while IFS= read -r FONT_FILE; do
    [ -n "$FONT_FILE" ] || continue

    FONT_URL="$FONT_BASE_URL/$(printf '%s' "$FONT_FILE" | sed 's/ /%20/g')"

    echo "Downloading $FONT_FILE..."

    curl -fL --progress-bar "$FONT_URL" \
        -o "$FONTS_DIR/$FONT_FILE"
done

# Refresh font cache
if command -v fc-cache >/dev/null 2>&1; then
    echo "Refreshing font cache..."
    fc-cache -f "$FONTS_DIR"
else
    echo "Warning: fc-cache not found. Install fontconfig to refresh the font cache."
fi

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
echo "Fonts: $FONTS_DIR"
echo ""
echo "Restart your terminal to use MesloLGS Nerd Font."
