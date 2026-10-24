"""WorkshopGuard launch gate: put this in a game's Steam launch options and it checks every mod before the game
starts.  "<venv>\\Scripts\\pythonw.exe" "<this file>" %command%   (see docs/GATE.md)"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from workshopguard.gate.__main__ import main  # noqa: E402

sys.exit(main())
