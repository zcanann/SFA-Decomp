#!/usr/bin/env python3
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    object_path = Path(sys.argv[1])
    objcopy = sys.argv[2]
    linker = sys.argv[3]
    alignments = sys.argv[4:]
    with tempfile.TemporaryDirectory(dir=object_path.parent) as directory:
        aligned = Path(directory) / "aligned.o"
        linked = Path(directory) / "linked.o"
        flags = []
        for alignment in alignments:
            flags.extend(("--set-section-alignment", alignment))
        subprocess.run([objcopy, *flags, object_path, aligned], check=True)
        subprocess.run([linker, "-r", aligned, "-o", linked], check=True)
        os.replace(linked, object_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
