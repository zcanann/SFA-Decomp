from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIGURE = REPO_ROOT / "configure.py"
LOCK_FILE = REPO_ROOT / "build" / ".sdk_try_linkage_flip.lock"


@dataclass(frozen=True)
class FlipResult:
    source: str
    ok: bool
    stage: str
    detail: str


class ConfigureLock:
    def __init__(self, timeout: int) -> None:
        self.timeout = timeout
        self.fd: int | None = None

    def __enter__(self) -> None:
        deadline = time.monotonic() + self.timeout
        LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        while True:
            try:
                self.fd = os.open(str(LOCK_FILE), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(self.fd, str(os.getpid()).encode("ascii"))
                return
            except FileExistsError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"timed out waiting for {LOCK_FILE}")
                time.sleep(0.25)

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        try:
            LOCK_FILE.unlink()
        except FileNotFoundError:
            pass


def object_suffix(source: str) -> str:
    return str(Path(source).with_suffix(".o")).replace("\\", "/")


def has_active_unit(source: str, version: str) -> bool:
    config_path = REPO_ROOT / "build" / version / "config.json"
    if not config_path.is_file():
        return False

    units = json.loads(config_path.read_text()).get("units", [])
    suffix = f"/obj/{object_suffix(source)}"
    for unit in units:
        obj = unit.get("object", "").replace("\\", "/")
        if obj.endswith(suffix):
            return True
    return False


def flip_config(config_text: str, source: str) -> str:
    pattern = re.compile(rf'Object\(NonMatching,\s*"{re.escape(source)}"')
    new_text, count = pattern.subn(f'Object(MatchingFor("GSAE01"), "{source}"', config_text, count=1)
    if count != 1:
        raise ValueError(f"could not find NonMatching object for {source}")
    return new_text


def write_config(config_text: str) -> None:
    CONFIGURE.write_text(config_text, newline="\n")


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
        "computed checksum",
        "FAILED:",
        "Linker Error:",
        "Compiler:",
    ):
        for line in lines:
            if needle in line:
                return line
    return lines[-1] if lines else "no output"


def try_flip(source: str, version: str, ninja_timeout: int, keep: bool, require_active_unit: bool) -> FlipResult:
    original = CONFIGURE.read_text()
    try:
        write_config(flip_config(original, source))

        configured = run_step(["python", "configure.py", "--matching"], timeout=120)
        if configured is None:
            write_config(original)
            return FlipResult(source, False, "configure", "timeout")
        if configured.returncode != 0:
            write_config(original)
            return FlipResult(source, False, "configure", summarize_failure(configured.stdout))
        active_unit = has_active_unit(source, version)
        if require_active_unit and not active_unit:
            write_config(original)
            return FlipResult(source, False, "active-unit", "not present in build config")

        built = run_step(["ninja"], timeout=ninja_timeout)
        if built is None:
            write_config(original)
            return FlipResult(source, False, "ninja", f"timeout>{ninja_timeout}s")
        if built.returncode != 0:
            write_config(original)
            return FlipResult(source, False, "ninja", summarize_failure(built.stdout))

        active_detail = "active-unit" if active_unit else "no-active-unit"
        if keep:
            return FlipResult(source, True, "kept", f"ninja ok {active_detail}")
        return FlipResult(source, True, "ninja", f"ok {active_detail}")
    finally:
        if not keep:
            write_config(original)


def main() -> None:
    parser = argparse.ArgumentParser(description="Temporarily flip NonMatching SDK objects and run the strict hash build.")
    parser.add_argument("sources", nargs="+", help="Source paths as they appear in configure.py")
    parser.add_argument("-v", "--version", default="GSAE01", help="Target version (default: GSAE01)")
    parser.add_argument("--ninja-timeout", type=int, default=30, help="ninja timeout in seconds (default: 30)")
    parser.add_argument("--lock-timeout", type=int, default=120, help="configure.py lock timeout in seconds (default: 120)")
    parser.add_argument("--keep-first-pass", action="store_true", help="Leave configure.py changed for the first passing source")
    parser.add_argument(
        "--require-active-unit",
        action="store_true",
        help="Fail flips whose object is not present in the generated build config",
    )
    args = parser.parse_args()

    try:
        with ConfigureLock(args.lock_timeout):
            for source in args.sources:
                result = try_flip(source, args.version, args.ninja_timeout, args.keep_first_pass, args.require_active_unit)
                status = "PASS" if result.ok else "FAIL"
                print(f"{status} stage={result.stage} path={result.source} detail={result.detail}")
                if result.ok and args.keep_first_pass:
                    break
    except TimeoutError as err:
        raise SystemExit(str(err)) from err


if __name__ == "__main__":
    main()
