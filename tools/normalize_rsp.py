from pathlib import Path
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: normalize_rsp.py <rspfile>", file=sys.stderr)
        return 1

    path = Path(sys.argv[1])
    data = path.read_text(encoding="utf-8")
    path.write_text(data, encoding="utf-8", newline="\r\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
