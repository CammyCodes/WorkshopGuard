"""Open a file read-only while refusing anyone else write or delete access, so it can't change between being
checked and the game reading it. Other readers (the game, Defender) are still allowed. Elsewhere it's a plain open."""

from __future__ import annotations

import os

if os.name == "nt":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.CreateFileW.restype = wintypes.HANDLE
    _k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                                 wintypes.DWORD, wintypes.HANDLE]
    _GENERIC_READ, _FILE_SHARE_READ, _OPEN_EXISTING, _SEQUENTIAL = 0x80000000, 0x1, 3, 0x08000000
    _INVALID = wintypes.HANDLE(-1).value

    def open_locked(path: str):
        p = os.path.abspath(path)
        if len(p) >= 250 and not p.startswith("\\\\?\\"):
            p = "\\\\?\\" + p
        h = _k32.CreateFileW(p, _GENERIC_READ, _FILE_SHARE_READ, None, _OPEN_EXISTING, _SEQUENTIAL, None)
        if h == _INVALID or h is None:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            fd = msvcrt.open_osfhandle(h, os.O_RDONLY | os.O_BINARY)
        except OSError:
            _k32.CloseHandle(wintypes.HANDLE(h))
            raise
        return os.fdopen(fd, "rb")
else:
    def open_locked(path: str):
        return open(path, "rb")
