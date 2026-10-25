# Contributing

Thanks for helping keep Workshops safe. The most useful contributions, roughly in order:

1. **Reports**: [missed malware](SECURITY.md#malware-it-missed) (privately, please) and
   [false alarms](https://github.com/CammyCodes/WorkshopGuard/issues/new?template=false_alarm.yml).
2. **Games**: per-game file checks for a game you know, or a fix for one that won't download
   ([Add a game](https://github.com/CammyCodes/WorkshopGuard/issues/new?template=add_game.yml)).
3. **Rules**: a YARA rule or a .NET analyzer rule for a trick WorkshopGuard doesn't catch yet.
4. **Mod loaders**: wiring [ModGuard](modguard/README.md) into a loader (BepInEx, MelonLoader, a game's own) so it
   checks mods before they load.

Questions and ideas go in [Discussions](https://github.com/CammyCodes/WorkshopGuard/discussions).

## Ground rules

- **No real malware in the repo, ever**, not even defanged. Test fixtures are built by `tests/build_fixtures.sh` from
  inert code: nothing in them is called, and every address is on the reserved `.invalid` domain. Describe a real
  sample by its SHA-256 instead.
- **Never write the EICAR test string out in full** in source. Antivirus will quarantine the file (and your
  checkout). `workshopguard/testdata.py` stores it reversed.
- **Every new rule comes with a test** that it fires, and a check that it stays quiet on clean mods. The clean set
  that matters most: HarmonyX/0Harmony, KitchenLib, other mod libraries and the game's own DLLs. A rule that flags Harmony will
  flag half the Workshop.
- **Keep the honesty.** Verdict text says what was found and why, never more. "What it can't do" in the README stays.

## Running it

The Python side runs in Docker:

```bash
sh tests/build_fixtures.sh
docker build -t workshopguard:test .
docker run --rm --entrypoint sh -v "$PWD/tests:/app/tests:ro" -e CLAMAV_HOST= workshopguard:test \
  -c "pip install -q --user pytest && python -m pytest -q -p no:cacheprovider /app/tests"
docker run --rm -e GAMES=bo3 workshopguard:test selftest bo3 --no-notify
```

ModGuard (C#) needs the .NET 8 SDK:

```bash
dotnet build modguard/ModGuard.csproj -c Release
dotnet test modguard/tests/ModGuard.Tests -c Release
```

## Changing the .NET rules

The .NET analyzer and file checks exist twice: in Python under `workshopguard/scan/` (scanner and launch gate) and
in C# under `modguard/src/` (`DotNetAnalyzer.cs`, `FileChecks.cs`, inside games). They must give the same answers:

1. Make the change in both.
2. Bump `EngineId` in `modguard/src/ModGuard.cs`, so players' cached results are checked again.
3. Build `modguard/tools/ModGuardCli` and run `modguard/tests/parity.py <ModGuardCli.exe> <folders of mods and
   DLLs>` (instructions at the top of the file). It must report 0 differences.

## Pull requests

Keep them small and say in the description what it catches (or stops catching) and how you tested it. CI builds the
image, runs the unit tests, a live self-test and the ModGuard tests on Linux and Windows. Add a line to
`CHANGELOG.md` under "Unreleased".

By contributing you agree your work is released under the [MIT licence](LICENSE).
