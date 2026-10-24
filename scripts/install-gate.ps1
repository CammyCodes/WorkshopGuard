# Sets up WorkshopGuard's launch gate on this PC: a Python environment next to the code (.gate\venv), YARA Forge's
# community rules, and the game's Steam launch options. Run it again any time to update the rules.
#   powershell -ExecutionPolicy Bypass -File scripts\install-gate.ps1 [-Game plateup] [-Uninstall]
param([string]$Game = "plateup", [switch]$Uninstall)
$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
$Gate = Join-Path $Repo ".gate"
$Py = Join-Path $Gate "venv\Scripts\python.exe"

if ($Uninstall) {
    & $Py -m workshopguard.gate uninstall $Game
    exit $LASTEXITCODE
}

if (-not (Test-Path $Py)) {
    $base = (Get-Command py -ErrorAction SilentlyContinue)
    if ($base) { & py -3 -m venv (Join-Path $Gate "venv") }
    else {
        $python = Get-Command python -ErrorAction SilentlyContinue
        if (-not $python) { Write-Error "Python 3.10+ isn't installed. Get it from python.org (tick 'Add to PATH'), then run this again." }
        & python -m venv (Join-Path $Gate "venv")
    }
}
& $Py -m pip install --quiet --disable-pip-version-check --upgrade "yara-python==4.5.4" "dnfile==0.18.0" "pefile==2024.8.26" "requests==2.34.2"
if ($LASTEXITCODE -ne 0) { Write-Error "Installing the scanner libraries failed." }

# YARA Forge "core": thousands of community rules for known malware families (the same set the Docker image uses).
$rules = Join-Path $Gate "rules"
New-Item -ItemType Directory -Force $rules | Out-Null
$zip = Join-Path $env:TEMP "wg-yara-forge-core.zip"
try {
    Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip" -OutFile $zip
    & $Py -I -c "import sys, zipfile; z = zipfile.ZipFile(sys.argv[1]); n = [m for m in z.namelist() if m.endswith('yara-rules-core.yar')][0]; open(sys.argv[2], 'wb').write(z.read(n))" $zip (Join-Path $rules "yara-rules-core.yar")
    Remove-Item $zip -Force
    Write-Host "YARA Forge rules updated."
} catch {
    Write-Warning "Couldn't download YARA Forge rules ($_). The gate still runs with its other engines."
}

Push-Location $Repo
try {
    & $Py -m workshopguard.gate scan $Game       # first full scan now, so the first launch is instant
    & $Py -m workshopguard.gate install $Game
} finally { Pop-Location }
