"""Compare C fixtures or the reconstructed Tricky TU across compiler versions.

Uses the active Tricky TU's flags, optionally overriding propagation. The
fixtures are independent of the recovered source and do not seed its data pool.
Outputs scratch objects and disassembly, not a compiler-provenance verdict.
With --whole-tu, compare the same current source against retail; --link also
checks its diagnostic game link. Source shaped under one compiler can bias
these results. A regression does not rule out another original compiler.
"""

import argparse
import subprocess
import sys
from pathlib import Path

import flag_probe
import strucdiff
from compiler_command import split_command_line


UNIT = "main/dlls/objects/196_Tricky/tricky"
SOURCE = """\
typedef unsigned long u32;

void setSignedMask(u32* flags) { *flags |= 0x10000; }
void setUnsignedMask(u32* flags) { *flags |= 0x10000u; }
void clearSignedMask(u32* flags) { *flags &= ~0x20; }
void clearUnsignedMask(u32* flags) { *flags &= ~0x20u; }

typedef struct PatchCache {
    short groups[4];
    float positions[4][3];
} PatchCache;
extern void showPatch(int index, float x, float y, float z);

void showCachedPatches(PatchCache* cache) {
    int i;
    for (i = 0; i < 4; i++) {
        if (cache->groups[i]) {
            showPatch(i, cache->positions[i][0], cache->positions[i][1], cache->positions[i][2]);
        }
    }
}
"""
FUNCTIONS = (
    "setSignedMask", "setUnsignedMask", "clearSignedMask",
    "clearUnsignedMask", "showCachedPatches",
)
RESIDUAL_FUNCTIONS = ("trickyDigTunnel", "moveTricky", "trickyUpdateMovementState")


def compile_command(base, compiler, source, directory, propagation):
    command = [arg for arg in base if arg != "-MMD"]
    compiler_index = next(i for i, arg in enumerate(command) if Path(arg).name == "mwcceppc.exe")
    command[compiler_index] = str(compiler)
    command[command.index("-c") + 1] = str(source)
    command[command.index("-o") + 1] = str(directory)
    if propagation != "current":
        command.extend(["-opt", "propagation" if propagation == "on" else "nopropagation"])
    return command


def report_tu(obj, functions):
    scores, error = flag_probe.score(UNIT, str(obj))
    if error is not None:
        raise RuntimeError(error)
    fuzzy, function_scores = scores
    exact = sum(value == 100.0 for value in function_scores.values())
    print(f"Current source vs retail: fuzzy={fuzzy:.5f}; {exact}/{len(function_scores)} functions exact")
    print("Code scores alone do not establish data or whole-link matching.")
    for name in functions:
        rows, _, _, target_count, source_count = strucdiff.analyse(UNIT, name, str(obj))
        if target_count == 0 and source_count == 0:
            raise ValueError(f"function absent from both objects: {name}")
        structure = sum(marker in "M+-" for marker, _, _ in rows)
        operands = sum(marker == "r" for marker, _, _ in rows)
        print(f"{name}: target {target_count} / ours {source_count}; STRUC {structure}; recolour {operands}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--versions", nargs="+", default=["1.3", "1.3.2", "2.0"])
    parser.add_argument("--propagation", choices=["current", "on", "off"], default="current")
    parser.add_argument("--whole-tu", action="store_true", help="compile current Tricky source instead of fixtures")
    parser.add_argument("--functions", nargs="+", help="whole-TU functions to inspect; defaults to the three residuals")
    parser.add_argument("--link", action="store_true", help="diagnostically link each whole-TU candidate")
    args = parser.parse_args()
    if (args.link or args.functions) and not args.whole_tu:
        parser.error("--link and --functions require --whole-tu")
    root = Path(flag_probe.ROOT)
    base = split_command_line(flag_probe.base_cmd(UNIT))
    if args.whole_tu:
        print("Same reconstructed source and active TU flags across versions; this is not compiler provenance.",
              flush=True)
    compilers = {}
    available = {entry.name for entry in (root / "build/compilers/GC").iterdir() if entry.is_dir()}
    for version in args.versions:
        compiler = root / "build/compilers/GC" / version / "mwcceppc.exe"
        if version not in available or not compiler.is_file():
            parser.error(f"compiler unavailable: {compiler}")
        compilers[version] = compiler
    for version, compiler in compilers.items():
        mode = "whole_" if args.whole_tu else ""
        directory = Path(flag_probe.SCRATCH) / f"tricky_compiler_{mode}{version}_{args.propagation}"
        directory.mkdir(parents=True, exist_ok=True)
        if args.whole_tu:
            source = root / "src/dlls/objects/196_Tricky/tricky.c"
        else:
            source = directory / "probe.c"
            source.write_text(SOURCE, encoding="ascii")
        command = compile_command(base, compiler, source, directory, args.propagation)
        result = subprocess.run(command, cwd=root, check=True, timeout=30,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if result.stdout:
            print(result.stdout.rstrip())
        if "Unknown option" in result.stdout:
            raise RuntimeError(f"GC/{version} ignored a requested compiler option")
        obj = directory / source.with_suffix(".o").name
        print(f"\nGC/{version}: {obj}", flush=True)
        if args.whole_tu:
            report_tu(obj, args.functions or RESIDUAL_FUNCTIONS)
            if args.link:
                sys.stdout.flush()
                subprocess.run(
                    [sys.executable, "tools/tricky_link_probe.py", "--object", str(obj),
                     "--output", str(directory / "link")], cwd=root, check=True, timeout=90,
                )
            continue
        for name in FUNCTIONS:
            print(name)
            for line in strucdiff.text_lines(str(obj), name):
                print("  " + line)


if __name__ == "__main__":
    main()
