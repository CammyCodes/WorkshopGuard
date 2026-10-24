"""Harmless test content for fake detections.

The EICAR string is the industry-standard antivirus test file: every scanner reports it, and it does nothing. It's
stored reversed and split so this source file itself doesn't trip antivirus on the machine you clone it to.
"""

from pathlib import Path

_EICAR_REVERSED = ("*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X", "")
MARKER = "WORKSHOPGUARD-FAKE-MALWARE-TEST-7f3a91"


def eicar() -> bytes:
    return "".join(_EICAR_REVERSED)[::-1].encode("ascii")


def plant(folder: Path) -> list[str]:
    """Drop the two fake-detection files into a downloaded item folder. Returns their names."""
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "workshopguard_eicar_test.txt").write_bytes(eicar())
    (folder / "workshopguard_marker_test.txt").write_text(
        f"This file was planted by WorkshopGuard's self-test. {MARKER}\n", encoding="ascii")
    return ["workshopguard_eicar_test.txt", "workshopguard_marker_test.txt"]
