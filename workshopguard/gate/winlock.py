"""Opening mod files on Windows through CreateFileW.

open_locked: read-only, refusing anyone else write or delete access, so a file can't change between being checked and
the game reading it. Other readers (the game, Defender) are still allowed.
open_shared: an ordinary read, but through the same API, so errors keep their Windows code (Python's open() turns
"your antivirus blocked this file", ERROR_VIRUS_INFECTED, into a meaningless EINVAL).
Elsewhere both are a plain open.
"""

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
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _GENERIC_READ, _OPEN_EXISTING, _SEQUENTIAL = 0x80000000, 3, 0x08000000
    _SHARE_READ, _SHARE_ALL = 0x1, 0x7
    _INVALID = wintypes.HANDLE(-1).value

    def _open(path: str, share: int):
        p = os.path.abspath(path)
        if len(p) >= 250 and not p.startswith("\\\\?\\"):
            p = "\\\\?\\" + p
        h = _k32.CreateFileW(p, _GENERIC_READ, share, None, _OPEN_EXISTING, _SEQUENTIAL, None)
        if h == _INVALID or h is None:
            err = ctypes.get_last_error()
            raise ctypes.WinError(err)
        try:
            fd = msvcrt.open_osfhandle(h, os.O_RDONLY | os.O_BINARY)
        except OSError:
            _k32.CloseHandle(h)
            raise
        return os.fdopen(fd, "rb")

    def open_locked(path: str):
        return _open(path, _SHARE_READ)

    def open_shared(path: str):
        return _open(path, _SHARE_ALL)
else:
    def open_locked(path: str):
        return open(path, "rb")

    def open_shared(path: str):
        return open(path, "rb")
