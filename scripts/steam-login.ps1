# Windows helper: saves STEAM_USERNAME in .env, then logs SteamCMD in once.
# You type the password and Steam Guard code into SteamCMD; only Steam's login token is kept (in the data volume).
Set-Location (Join-Path $PSScriptRoot "..")

$user = Read-Host "Steam account name (the one you sign in with, not your profile name)"
if (-not $user) { Write-Host "No account name given."; exit 1 }

if (-not (Test-Path ".env")) { Copy-Item ".env.example" ".env" }
$lines = @(Get-Content ".env")
if ($lines -match '^STEAM_USERNAME=') {
    $lines = $lines -replace '^STEAM_USERNAME=.*', "STEAM_USERNAME=$user"
} else {
    $lines += "STEAM_USERNAME=$user"
}
Set-Content ".env" $lines -Encoding ascii
Write-Host "Saved STEAM_USERNAME=$user to .env"

docker compose run --rm guard login $user
if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "Logged in. Restart the watcher to use it: docker compose up -d"
}
