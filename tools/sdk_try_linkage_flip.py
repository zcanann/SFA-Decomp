from __future__ import annotations

import argparse
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIGURE = REPO_ROOT / "configure.py"


@dataclass(frozen=True)
class FlipResult:
    source: str
    ok: bool
    stage: str
    detail: str


def flip_config(config_text: str, source: str) -> str:
    pattern = re.compile(rf'Object\(NonMatching,\s*"{re.escape(source)}"')
    new_text, count = pattern.subn(f'Object(MatchingFor("GSAE01"), "{source}"', config_text, count=1)
    if count != 1:
        raise ValueError(f"could not find NonMatching object for {source}")
    return new_text


def run_step(command: list[str], timeout: int) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            command,
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None


def summarize_failure(output: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    for needle in (
        "multiply-defined:",
        "undefined:",
        "FAILED:",
        "computed checksum",
        "Linker Error:",
        "Compiler:",
    ):
        for line in lines:
            if needle in line:
                return line
    return lines[-1] if lines else "no output"


def try_flip(source: str, ninja_timeout: int, keep: bool) -> FlipResult:
    original = CONFIGURE.read_text()
    try:
        CONFIGURE.write_text(flip_config(original, source))

        configured = run_step(["python", "configure.py", "--matching"], timeout=120)
        if configured is None:
            return FlipResult(source, False, "configure", "timeout")
        if configured.returncode != 0:
            return FlipResult(source, False, "configure", summarize_failure(configured.stdout))

        built = run_step(["ninja"], timeout=ninja_timeout)
        if built is None:
            return FlipResult(source, False, "ninja", f"timeout>{ninja_timeout}s")
        if built.returncode != 0:
            return FlipResult(source, False, "ninja", summarize_failure(built.stdout))

        if keep:
            return FlipResult(source, True, "kept", "ninja ok")
        return FlipResult(source, True, "ninja", "ok")
    finally:
        if not keep:
            CONFIGURE.write_text(original)


def main() -> None:
    parser = argparse.ArgumentParser(description="Temporarily flip NonMatching SDK objects and run the strict hash build.")
    parser.add_argument("sources", nargs="+", help="Source paths as they appear in configure.py")
    parser.add_argument("--ninja-timeout", type=int, default=30, help="ninja timeout in seconds (default: 30)")
    parser.add_argument("--keep-first-pass", action="store_true", help="Leave configure.py changed for the first passing source")
    args = parser.parse_args()

    for source in args.sources:
        result = try_flip(source, args.ninja_timeout, args.keep_first_pass)
        status = "PASS" if result.ok else "FAIL"
        print(f"{status} stage={result.stage} path={result.source} detail={result.detail}")
        if result.ok and args.keep_first_pass:
            break


if __name__ == "__main__":
    main()
