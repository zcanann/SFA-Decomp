#!/usr/bin/env python3
"""Lift retail SFA functions, optionally scoring with the owning TU's compiler."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

from compiler_command import split_command_line
from function_objdump import load_units, resolve_unit

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "tools/asmlift/node_modules/@asmlift/cli/dist/asmlift.mjs"


def candidate_command(command: str, source: str) -> list[str]:
    """Keep the exact compiler/flags; redirect only source, output and deps."""
    argv = split_command_line(command)
    if "&&" in argv:
        end = argv.index("&&")
        tail = argv[end + 1:]
        if len(tail) != 4 or tail[1] != "tools/transform_dep.py":
            raise ValueError("Unrecognized post-compile command")
        argv = argv[:end]
    if any(token in argv for token in ("&&", ";", "|", ">", "<")):
        raise ValueError("Unrecognized shell syntax in compiler command")
    if not any(Path(token).name.lower() == "mwcceppc.exe" for token in argv):
        raise ValueError("Only MWCC units are supported (zlb must stay on ProDG)")
    if argv.count("-c") != 1 or argv.count("-o") != 1:
        raise ValueError("Expected one compile input and output")
    if any(argv.index(option) + 1 >= len(argv) for option in ("-c", "-o")):
        raise ValueError("Missing compiler input or output argument")
    index = argv.index("-c") + 1
    if Path(argv[index]) != Path(source):
        raise ValueError(f"Unexpected compiler source: {argv[index]}")
    argv[index] = "{input}"
    argv[argv.index("-o") + 1] = "{output}"
    return [token for token in argv if token != "-MMD"]


def lift(args: argparse.Namespace) -> int:
    if os.name == "nt":
        raise ValueError("This adapter currently requires a POSIX host (asmlift uses sh)")
    if not CLI.is_file():
        raise ValueError("Install first: npm ci --prefix tools/asmlift --ignore-scripts")
    unit = resolve_unit(load_units(ROOT / "build" / args.version / "config.json"), args.unit)
    target = ROOT / unit["object"]
    entries = json.loads((ROOT / "objdiff.json").read_text())["units"]
    matches = [entry for entry in entries if entry.get("target_path") == unit["object"]]
    if len(matches) != 1 or not matches[0].get("base_path"):
        raise ValueError("Unit needs a configured source build in objdiff.json; configure this version first")
    entry = matches[0]
    if not target.is_file():
        raise ValueError(f"Missing retail object: {target}; run the matching build first")
    commands = subprocess.check_output(
        ["ninja", "-t", "commands", entry["base_path"]], cwd=ROOT, text=True
    ).strip().splitlines()
    if not commands:
        raise ValueError("Ninja returned no compiler command for this unit")
    argv = candidate_command(commands[-1], entry["metadata"]["source_path"])
    objdump = ROOT / "build/binutils/powerpc-eabi-objdump"
    if not objdump.is_file():
        raise ValueError(f"Missing host objdump: {objdump}")
    scratch = ROOT / "build/asmlift" / args.version
    scratch.mkdir(parents=True, exist_ok=True)
    workspace = Path(tempfile.mkdtemp(prefix="lift-", dir=scratch))
    manifest = workspace / "compile.json"
    manifest.write_text(json.dumps({
        "unit": unit["name"], "symbol": args.symbol,
        "target": str(target), "compiler_argv": argv,
        "asmlift_model": args.model,
    }, indent=2) + "\n")
    compiler_index = next(i for i, token in enumerate(argv) if Path(token).name.lower() == "mwcceppc.exe")
    flags = argv[compiler_index + 1:]
    for option in ("-c", "-o"):
        index = flags.index(option)
        del flags[index:index + 2]
    compiler = (
        "cd " + shlex.quote(str(ROOT)) + " && " + shlex.join(argv[:compiler_index + 1])
        + " {{cflags}} -c '{{inputPath}}' -o '{{outputPath}}'"
    )
    settings = {"target": args.model, "objdump": str(objdump), "compiler": compiler}
    if args.elf:
        settings["elf"] = str(args.elf.resolve())
    config = workspace / "decomp.yaml"
    # JSON is a YAML subset and avoids a Python YAML dependency.
    config.write_text(json.dumps({"platform": "gc", "tools": {"asmlift": settings}}, indent=2) + "\n")
    command = ["node", str(CLI), str(target), "--name", args.symbol, "--config", str(config),
               "--cflags", shlex.join(flags)]
    if args.score:
        command += ["--score-against", str(target), "--progress"]
    if args.strict:
        command.append("--strict")
    if args.proto:
        command += ["--proto", str(args.proto.resolve())]
    print(f"Workspace: {workspace}", file=sys.stderr)
    print(f"Model: {args.model} (heuristic); scoring uses the unit's actual MWCC and flags", file=sys.stderr)
    # Fresh compiles keep the result independent of upstream's persistent cache.
    env = dict(os.environ, ASMLIFT_CANDCACHE="off")
    (workspace / "command.json").write_text(json.dumps(command, indent=2) + "\n")
    with (workspace / "candidate.c").open("w") as candidate, (workspace / "diagnostics.log").open("w") as log:
        with subprocess.Popen(command, cwd=ROOT, stdout=candidate, stderr=subprocess.PIPE,
                              text=True, env=env) as process:
            assert process.stderr is not None
            for line in process.stderr:
                sys.stderr.write(line)
                log.write(line)
            code = process.wait()
    print(f"Candidate: {workspace / 'candidate.c'} (exit {code})", file=sys.stderr)
    return code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("lift", help="Write a candidate under build/asmlift")
    run.add_argument("unit", help="e.g. main/pad.c (from build/<version>/config.json)")
    run.add_argument("symbol")
    run.add_argument("--version", default="GSAE01")
    run.add_argument("--score", action="store_true", help="Compile and objdiff-score candidates")
    run.add_argument("--strict", action="store_true", help="Decline unsupported assembly")
    run.add_argument("--proto", type=Path, help="Asmlift prototype JSON")
    run.add_argument("--elf", type=Path, help="Optional linked ELF for symbol/type hints")
    run.add_argument("--model", default="mwcc_242_81",
                     choices=["mwcc_242_81", "mwcc_233_163n", "mwcc_247_107"])
    args = parser.parse_args()
    try:
        return lift(args)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"asmlift-sfa: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
