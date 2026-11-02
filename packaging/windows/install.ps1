
$ErrorActionPreference = "Stop"

# ============================================================
# Configuration
# ============================================================

$AppName = "Redoubt"
$Repo = "FreyFlyy/Redoubt"
$Branch = "main"

$InstallDir = Join-Path $env:USERPROFILE ".redoubt"

$ExePath = Join-Path $InstallDir "Redoubt.exe"
$IconPng = Join-Path $InstallDir "redoubt.png"
$IconIco = Join-Path $InstallDir "redoubt.ico"

$ReleaseApi = "https://api.github.com/repos/$Repo/releases/latest"

$RawBaseUrl = "https://raw.githubusercontent.com/$Repo/$Branch"

$IconUrl = "$RawBaseUrl/packaging/redoubt.png"
$FontBaseUrl = "$RawBaseUrl/packaging/fonts"

$FontFiles = @(
    "MesloLGS NF Regular.ttf",
    "MesloLGS NF Bold.ttf",
    "MesloLGS NF Italic.ttf",
    "MesloLGS NF Bold Italic.ttf"
)

$UserFonts = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Fonts"
$FontRegistry = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Fonts"

# ============================================================
# Header
# ============================================================

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "          REDOUBT INSTALLER           " -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# 1. Download latest release
# ============================================================

Write-Host "[1/5] Downloading latest Redoubt release..." -ForegroundColor Cyan

$Release = Invoke-RestMethod `
    -Uri $ReleaseApi `
    -Headers @{
        "Accept" = "application/vnd.github+json"
        "User-Agent" = "Redoubt-Installer"
    }

$Version = $Release.tag_name -replace '^v', ''
$ExpectedAssetName = "Redoubt-$Version-x86_64.exe"

$Asset = $Release.assets |
    Where-Object {
        $_.name -eq $ExpectedAssetName -and
        $_.state -eq "uploaded" -and
        $_.size -gt 0
    } |
    Select-Object -First 1

if (-not $Asset) {
    throw "Windows executable not found in release $($Release.tag_name). Expected: $ExpectedAssetName"
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$TempExe = Join-Path $env:TEMP "$([guid]::NewGuid()).exe"

try {
    Invoke-WebRequest `
        -Uri $Asset.browser_download_url `
        -OutFile $TempExe

    if (-not (Test-Path $TempExe) -or (Get-Item $TempExe).Length -eq 0) {
        throw "Downloaded executable is missing or empty."
    }

    Move-Item -Path $TempExe -Destination $ExePath -Force
}
finally {
    if (Test-Path $TempExe) {
        Remove-Item $TempExe -Force
    }
}

Write-Host "Installed version: $($Release.tag_name)" -ForegroundColor Green

# ============================================================
# 2. Download icon and install fonts
# ============================================================

Write-Host ""
Write-Host "[2/5] Installing application resources..." -ForegroundColor Cyan

# Download Redoubt icon

Write-Host "Downloading Redoubt icon..."

Invoke-WebRequest `
    -Uri $IconUrl `
    -OutFile $IconPng

if (-not (Test-Path $IconPng) -or (Get-Item $IconPng).Length -eq 0) {
    throw "Failed to download Redoubt icon."
}

# Convert PNG to ICO

Add-Type -AssemblyName System.Drawing

$Bitmap = [System.Drawing.Bitmap]::FromFile($IconPng)

try {
    $IconHandle = $Bitmap.GetHicon()

    try {
        $Icon = [System.Drawing.Icon]::FromHandle($IconHandle)

        try {
            $IconStream = [System.IO.File]::Create($IconIco)

            try {
                $Icon.Save($IconStream)
            }
            finally {
                $IconStream.Dispose()
            }
        }
        finally {
            $Icon.Dispose()
        }
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::DestroyIcon($IconHandle)
    }
}
finally {
    $Bitmap.Dispose()
}

Write-Host "Redoubt icon installed." -ForegroundColor Green

# Install MesloLGS Nerd Font

Write-Host "Installing MesloLGS Nerd Font..."

New-Item -ItemType Directory -Force -Path $UserFonts | Out-Null
New-Item -Path $FontRegistry -Force | Out-Null

foreach ($FontFile in $FontFiles) {
    $Destination = Join-Path $UserFonts $FontFile
    $EncodedName = [uri]::EscapeDataString($FontFile)
    $Url = "$FontBaseUrl/$EncodedName"

    try {
        Invoke-WebRequest `
            -Uri $Url `
            -OutFile $Destination

        if ((Get-Item $Destination).Length -eq 0) {
            throw "Downloaded font is empty."
        }

        $RegistryName = "$([System.IO.Path]::GetFileNameWithoutExtension($FontFile)) (TrueType)"

        New-ItemProperty `
            -Path $FontRegistry `
            -Name $RegistryName `
            -Value $Destination `
            -PropertyType String `
            -Force | Out-Null

        Write-Host "  Installed: $FontFile" -ForegroundColor Green
    }
    catch {
        Write-Warning "Could not install $FontFile : $_"
    }
}

# ============================================================
# 3. Check / install Windows Terminal
# ============================================================

Write-Host ""
Write-Host "[3/5] Checking Windows Terminal..." -ForegroundColor Cyan

$WT = Get-Command "wt.exe" -ErrorAction SilentlyContinue

if (-not $WT) {
    $Winget = Get-Command "winget.exe" -ErrorAction SilentlyContinue

    if ($Winget) {
        Write-Host "Installing Windows Terminal..."

        try {
            & $Winget.Source install `
                --id Microsoft.WindowsTerminal `
                --exact `
                --source winget `
                --silent `
                --accept-package-agreements `
                --accept-source-agreements

            $WT = Get-Command "wt.exe" -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warning "Windows Terminal installation failed: $_"
        }
    }
    else {
        Write-Warning "winget is not installed."

        Write-Host "Opening Microsoft Store - App Installer..."

        Start-Process "ms-windows-store://pdp/?ProductId=9NBLGGH4NNS1"

        Write-Warning "Install App Installer to enable winget."
    }
}

if ($WT) {
    Write-Host "Windows Terminal available." -ForegroundColor Green
}
else {
    Write-Warning "Windows Terminal unavailable. Shortcuts will use PowerShell."
}

# ============================================================
# 4. Create shortcuts
# ============================================================

Write-Host ""
Write-Host "[4/5] Creating shortcuts..." -ForegroundColor Cyan

$WshShell = New-Object -ComObject WScript.Shell

$Desktop = [Environment]::GetFolderPath("Desktop")

$StartMenu = Join-Path $env:APPDATA `
    "Microsoft\Windows\Start Menu\Programs\Redoubt"

New-Item -ItemType Directory -Force -Path $StartMenu | Out-Null

$ShortcutPaths = @(
    (Join-Path $Desktop "Redoubt.lnk"),
    (Join-Path $StartMenu "Redoubt.lnk")
)

foreach ($ShortcutPath in $ShortcutPaths) {
    $Shortcut = $WshShell.CreateShortcut($ShortcutPath)

    if ($WT) {
        $Shortcut.TargetPath = $WT.Source
        $Shortcut.Arguments = "-w new powershell.exe -NoLogo -NoExit -Command `"& '$ExePath'`""
    }
    else {
        $Shortcut.TargetPath = "powershell.exe"
        $Shortcut.Arguments = "-NoLogo -NoExit -Command `"& '$ExePath'`""
    }

    $Shortcut.WorkingDirectory = $InstallDir
    $Shortcut.IconLocation = "$IconIco,0"
    $Shortcut.Description = "A peer-to-peer messaging app with end-to-end message encryption and hardened client runtime"

    $Shortcut.Save()

    Write-Host "  Created: $ShortcutPath" -ForegroundColor Green
}

# ============================================================
# 5. Finish
# ============================================================

Write-Host ""
Write-Host "[5/5] Installation complete!" -ForegroundColor Green

Write-Host ""
Write-Host "Installation directory:"
Write-Host "  $InstallDir"

Write-Host ""
Write-Host "Installed files:"
Write-Host "  Redoubt.exe"
Write-Host "  redoubt.png"
Write-Host "  redoubt.ico"

Write-Host ""
Write-Host "Shortcuts:"
Write-Host "  Desktop"
Write-Host "  Start Menu"

Write-Host ""
Write-Host "Restart Windows Terminal to load the installed font."

Write-Host ""
Write-Host "======================================" -ForegroundColor Green
Write-Host "       REDOUBT INSTALLED SUCCESSFULLY  " -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green
Write-Host ""
