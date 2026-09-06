"""Measure a game-code compiler migration without changing the active build.

Rebuilds the current GC/2.0 and GC/1.3 game units using their configured
compiler and a candidate compiler, preserving flags and section postprocessing.
Use --all-mwcc-game to include older game-category math compiler overrides.
SDK/MSL/MusyX units outside that category and the ProDG decompressor stay unchanged.
Run configure.py --matching, ninja, and ninja all_source before this tool.
This measures migration cost for the current source, not compiler provenance.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import time

from compiler_command import split_command_line
import obj_equal


ROOT = Path(__file__).resolve().parents[1]


def run(command, timeout=30):
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def compile_unit(unit, commands, output, compiler, extra_cflags=()):
    result = {"name": unit["name"], "source": unit["metadata"]["source_path"],
              "currently_linked": unit["metadata"].get("complete", False)}
    original = ROOT / unit["base_path"]
    first = commands[0]
    index = next(i for i, token in enumerate(first) if Path(token).name == "mwcceppc.exe")
    result["original_compiler"] = str(Path(first[index]).parent.relative_to("build/compilers"))
    result["source_sha256"] = hashlib.sha256((ROOT / result["source"]).read_bytes()).hexdigest()
    for variant in ("baseline", "candidate"):
        obj = output / variant / Path(unit["base_path"]).relative_to("build/GSAE01/src")
        obj.parent.mkdir(parents=True, exist_ok=True)
        obj.unlink(missing_ok=True)
        command = first.copy()
        if variant == "candidate":
            command[index] = str(ROOT / "build/compilers" / compiler / "mwcceppc.exe")
            command.extend(extra_cflags)
        command = [token for token in command if token != "-MMD"]
        command[command.index("-o") + 1] = str(obj.parent)
        actions = [command]
        for post in commands[1:]:
            if any(Path(token).name == "transform_dep.py" for token in post):
                continue
            actions.append([str(obj) if token in (unit["base_path"], str(original)) else token
                            for token in post])
        result[variant] = {"object": str(obj), "commands": actions}
        log = []
        try:
            for action in actions:
                proc = run(action)
                log.append(proc.stdout + proc.stderr)
                if proc.returncode or "Unknown option" in log[-1]:
                    raise RuntimeError(f"command failed ({proc.returncode})")
            if not obj.is_file():
                raise RuntimeError("compiler emitted no object")
            result[variant]["ok"] = True
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            result[variant].update(ok=False, error=str(error))
            obj.unlink(missing_ok=True)
        obj.with_suffix(".log").write_text("\n".join(log))
    if all(result[v]["ok"] for v in ("baseline", "candidate")):
        differences = obj_equal.compare(result["baseline"]["object"], result["candidate"]["object"])
        result["object_differences"] = differences
        result["substantive_object_differences"] = [
            diff for diff in differences
            if not diff.startswith("ANON:") and not diff.startswith("CONTENT: section .comment ")
        ]
    return result


def generate_report(project, rows, output, variant):
    config = copy.deepcopy(project)
    lookup = {row["name"]: row for row in rows}
    for unit in config["units"]:
        for key in ("target_path", "base_path"):
            if unit.get(key):
                unit[key] = str(ROOT / unit[key])
        unit.pop("scratch", None)
        if unit["name"] in lookup:
            result = lookup[unit["name"]][variant]
            # A failed candidate must stay absent, never silently use the baseline.
            if result["ok"]:
                unit["base_path"] = result["object"]
            else:
                unit.pop("base_path", None)
                unit.setdefault("metadata", {})["complete"] = False
    directory = output / (variant + "_report")
    write_json(directory / "objdiff.json", config)
    report = directory / "report.json"
    proc = run([str(ROOT / "build/tools/objdiff-cli"), "report", "generate",
                "-p", str(directory), "-o", str(report)], timeout=60)
    (directory / "report.log").write_text(proc.stdout + proc.stderr)
    if proc.returncode:
        raise RuntimeError(f"objdiff failed: {directory / 'report.log'}")
    return json.loads(report.read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", default="GC/1.3")
    parser.add_argument("--all-mwcc-game", action="store_true",
                        help="include game-category MWCC units with older library compiler overrides")
    parser.add_argument("--extra-cflags", default="",
                        help="additional candidate-only compiler flags")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=6)
    args = parser.parse_args()
    output = args.output.resolve()
    if not (ROOT / "build/compilers" / args.compiler / "mwcceppc.exe").is_file():
        parser.error("candidate compiler is unavailable")
    if output.exists():
        parser.error("output directory must be new, to prevent stale probe results")
    project = json.loads((ROOT / "objdiff.json").read_text())
    game = [unit for unit in project["units"]
            if "game" in unit.get("metadata", {}).get("progress_categories", [])]
    proc = run(["ninja", "-t", "commands", *[unit["base_path"] for unit in game]])
    if proc.returncode:
        raise RuntimeError(proc.stderr)
    commands = {}
    for line in proc.stdout.splitlines():
        if "mwcceppc.exe" not in line:
            continue
        actions = [split_command_line(part) for part in line.split(" && ")]
        first = actions[0]
        if "-c" in first:
            commands[first[first.index("-c") + 1]] = actions
    selected, excluded = [], []
    for unit in game:
        source = unit["metadata"]["source_path"]
        actions = commands.get(source)
        if not actions:
            excluded.append({"name": unit["name"], "reason": "not compiled with MWCC"})
            continue
        executable = next(token for token in actions[0] if Path(token).name == "mwcceppc.exe")
        version = str(Path(executable).parent.relative_to("build/compilers"))
        if not args.all_mwcc_game and version not in ("GC/2.0", "GC/1.3"):
            excluded.append({"name": unit["name"], "reason": "library compiler " + version})
            continue
        selected.append(unit)
    start = time.monotonic()
    manifest = {"commit": run(["git", "rev-parse", "HEAD"]).stdout.strip(),
                "candidate_compiler": args.compiler, "extra_cflags": args.extra_cflags,
                "excluded_game_category_units": excluded,
                "selected_units": len(selected), "rows": []}
    write_json(output / "manifest.json", manifest)
    print(f"Rebuilding {len(selected)} game units twice; {len(excluded)} category entries excluded.", flush=True)
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        pending = [pool.submit(compile_unit, unit, commands[unit["metadata"]["source_path"]],
                               output, args.compiler, split_command_line(args.extra_cflags))
                   for unit in selected]
        for future in as_completed(pending):
            manifest["rows"].append(future.result())
            count = len(manifest["rows"])
            if count % 100 == 0 or count == len(selected):
                print(f"Compiled {count}/{len(selected)} in {time.monotonic() - start:.1f}s", flush=True)
    manifest["rows"].sort(key=lambda row: row["name"])
    write_json(output / "manifest.json", manifest)
    reports = {variant: generate_report(project, manifest["rows"], output, variant)
               for variant in ("baseline", "candidate")}
    for row in manifest["rows"]:
        for variant in ("baseline", "candidate"):
            unit = next(u for u in reports[variant]["units"] if u["name"] == row["name"])
            row[variant]["measures"] = unit.get("measures", {})
            row[variant]["functions"] = {f["name"]: {"size": int(f.get("size", 0)),
                "fuzzy": f.get("fuzzy_match_percent", 0)} for f in unit.get("functions", [])}
    manifest["elapsed_seconds"] = time.monotonic() - start
    manifest["full_report_measures"] = {v: reports[v]["measures"] for v in reports}
    manifest["full_report_categories"] = {v: reports[v].get("categories", []) for v in reports}
    write_json(output / "manifest.json", manifest)
    print(json.dumps(manifest["full_report_measures"], indent=2), flush=True)
    print(f"Results: {output / 'manifest.json'}", flush=True)


if __name__ == "__main__":
    main()
