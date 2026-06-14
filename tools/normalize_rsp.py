from pathlib import Path
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: normalize_rsp.py <rspfile>", file=sys.stderr)
        return 1

    path = Path(sys.argv[1])
    data = path.read_text(encoding="utf-8")
    # Normalize all line endings to CRLF, version-agnostically (Path.write_text
    # only gained the `newline` kwarg in Python 3.10; this also works on 3.9).
    normalized = data.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
    path.write_bytes(normalized.encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
