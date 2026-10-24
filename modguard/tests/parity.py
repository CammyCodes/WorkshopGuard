"""Compares ModGuard (C#) with WorkshopGuard's Python engine, file by file: the same capabilities and the same
findings (rules) for every program it's given. Run from the repo root with the gate's venv:

    .gate\\venv\\Scripts\\python modguard\\tests\\parity.py <ModGuardCli.exe> <folder or file>...

Only the file checks, Windows program checks and .NET analysis are compared: YARA and antivirus engines aren't in
ModGuard (it asks the player's antivirus instead).
"""

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from workshopguard import games  # noqa: E402
from workshopguard.scan import engine  # noqa: E402

EXTS = (".dll", ".exe", ".pyd", ".zip")


def files(args):
    for a in args:
        p = Path(a)
        if p.is_file():
            yield p
        else:
            for f in sorted(p.rglob("*")):
                if f.is_file() and f.suffix.lower() in EXTS and f.stat().st_size < 64 * 1024 * 1024:
                    yield f


def python_view(path: Path):
    s = engine._Scan(games.profile_for(1599600), engine.Scanners())
    data, size, sha = engine._read(path)
    s.file(path.name, data, size, sha)
    rules = sorted({f.rule for f in s.findings if f.severity != "info"})
    caps = set()
    for d in s.details.values():
        caps |= set(d.get("capabilities", []))
    return sorted(caps), rules


def main() -> int:
    cli, targets = sys.argv[1], sys.argv[2:]
    todo = list(files(targets))
    cs = {}
    for i in range(0, len(todo), 200):
        out = subprocess.run([cli, "analyze", *map(str, todo[i:i + 200])], capture_output=True, text=True, check=True)
        for line in out.stdout.splitlines():
            r = json.loads(line)
            cs[os.path.normcase(r["file"])] = (sorted(r["capabilities"]), sorted(r["rules"]))
    same = differ = 0
    for f in todo:
        py = python_view(f)
        c = cs[os.path.normcase(str(f))]
        if py == c:
            same += 1
            continue
        differ += 1
        print(f"DIFF {f}")
        for label, a, b in (("capabilities", py[0], c[0]), ("rules", py[1], c[1])):
            if a != b:
                print(f"   {label}: python only {sorted(set(a) - set(b))}, C# only {sorted(set(b) - set(a))}")
    print(f"{same} files identical, {differ} different, out of {len(todo)}")
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
