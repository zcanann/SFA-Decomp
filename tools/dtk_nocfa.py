#!/usr/bin/env python3
"""Build the pinned DTK nocfa prototype; see docs/foreign/joint_matrices.md."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "tools/patches/dtk-nocfa.patch"
UPSTREAM = "https://github.com/encounter/decomp-toolkit.git"
REVISION = "e4219e7644fb7b96d920d5bc3d1d950f5569dcaf"  # v1.8.3
SYMBOL = "modelAnimBuildJointMatrices = .text:0x80006C6C; // type:label"
ANNOTATED = SYMBOL.replace("type:label", "type:function size:0x130C nocfa")


def cache_dir(build_dir: Path) -> Path:
    digest = hashlib.sha256(REVISION.encode() + PATCH.read_bytes()).hexdigest()[:16]
    return build_dir / "tools" / f"dtk-nocfa-{digest}"


def binary_path(build_dir: Path) -> Path:
    name = "dtk.exe" if os.name == "nt" else "dtk"
    return cache_dir(build_dir) / "target/release" / name


def run(*args: str | Path, cwd: Path | None = None) -> None:
    subprocess.run([str(arg) for arg in args], cwd=cwd, check=True)


def build(build_dir: Path, test: bool) -> Path:
    cache = cache_dir(build_dir).resolve()
    source = cache / "source"
    cache.mkdir(parents=True, exist_ok=True)
    if not source.exists():
        # Prepare a new checkout atomically. Never reset an existing checkout.
        with tempfile.TemporaryDirectory(prefix="prepare-", dir=cache) as tmp:
            checkout = Path(tmp) / "source"
            run("git", "init", "--quiet", checkout)
            run("git", "fetch", "--quiet", "--depth", "1", UPSTREAM, REVISION, cwd=checkout)
            run("git", "checkout", "--quiet", "--detach", "FETCH_HEAD", cwd=checkout)
            run("git", "apply", "--check", PATCH, cwd=checkout)
            run("git", "apply", PATCH, cwd=checkout)
            checkout.rename(source)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    diff = subprocess.check_output(["git", "diff", "--no-ext-diff", "--binary"], cwd=source)
    if head != REVISION or diff != PATCH.read_bytes():
        raise RuntimeError(f"Modified DTK checkout: {source}; preserve it and use another --build-dir")
    cargo = ["cargo", "build", "--locked", "--release", "--manifest-path", source / "Cargo.toml",
             "--target-dir", cache / "target"]
    run(*cargo)
    if test:
        cargo[1] = "test"
        run(*cargo)
    return binary_path(build_dir)


def write_changed(path: Path, text: str) -> None:
    if not path.exists() or path.read_text(encoding="utf-8") != text:
        path.write_text(text, encoding="utf-8")


def write_overlay(build_dir: Path) -> tuple[Path, Path]:
    """Use a generated config so ordinary builds retain upstream DTK behavior."""
    directory = build_dir / "GSAE01/joint-matrices-nocfa"
    directory.mkdir(parents=True, exist_ok=True)
    symbols = (ROOT / "config/GSAE01/symbols.txt").read_text(encoding="utf-8")
    if symbols.count(SYMBOL + "\n") != 1:
        raise RuntimeError("Joint-matrix symbol changed; re-audit the nocfa boundary before use")
    symbols_path = directory / "symbols.txt"
    config_path = directory / "config.yml"
    config = (ROOT / "config/GSAE01/config.yml").read_text(encoding="utf-8")
    stamp_path = directory / "inputs.sha256"
    digest = hashlib.sha256((symbols + config + ANNOTATED).encode()).hexdigest()
    # DTK may normalize or enrich the generated symbols. Keep those results
    # across configure reruns unless the canonical inputs actually changed.
    if (stamp_path.exists() and stamp_path.read_text() == digest
            and symbols_path.exists() and config_path.exists()):
        return config_path, symbols_path
    original = "symbols: config/GSAE01/symbols.txt"
    if config.count(original) != 1:
        raise RuntimeError("EN DTK symbols path changed; update the nocfa overlay")
    # JSON strings are valid quoted YAML scalars, including paths with spaces.
    write_changed(symbols_path, symbols.replace(SYMBOL + "\n", ANNOTATED + "\n"))
    write_changed(config_path, config.replace(original, f"symbols: {json.dumps(str(symbols_path))}"))
    stamp_path.write_text(digest)
    return config_path, symbols_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=Path("build"))
    parser.add_argument("--test", action="store_true", help="also run DTK's tests")
    args = parser.parse_args()
    os.chdir(ROOT)
    binary = build(args.build_dir, args.test)
    print(f"Built {binary}")
    print("Enable: python3 configure.py --matching --joint-matrices-nocfa")
    print("Disable: python3 configure.py --matching")


if __name__ == "__main__":
    main()
