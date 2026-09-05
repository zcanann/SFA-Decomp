"""Split one compiler invocation using host argument quoting, not shell syntax."""

import ctypes
import os
import shlex


def split_command_line(command: str) -> list[str]:
    if "\0" in command:
        raise ValueError("command line contains a NUL byte")
    command = command.strip()
    if not command:
        return []
    if os.name != "nt":
        return shlex.split(command)

    # POSIX shlex consumes unquoted path backslashes. Rewriting them to slashes
    # also changes literal macro/pragma arguments, so use the native parser.
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    parse = shell32.CommandLineToArgvW
    parse.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
    parse.restype = ctypes.POINTER(ctypes.c_wchar_p)
    release = kernel32.LocalFree
    release.argtypes = [ctypes.c_void_p]
    release.restype = ctypes.c_void_p

    count = ctypes.c_int()
    arguments = parse(command, ctypes.byref(count))
    if not arguments:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return list(arguments[:count.value])
    finally:
        release(ctypes.cast(arguments, ctypes.c_void_p))
