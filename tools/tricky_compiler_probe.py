"""Compare ordinary C mask and indexed-loop shapes across Tricky compilers.

Uses the active Tricky TU's flags, optionally overriding propagation. The
fixtures are independent of the recovered source and do not seed its data pool.
Outputs scratch objects and disassembly, not a compiler-provenance verdict.
"""

import argparse
import subprocess
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--versions", nargs="+", default=["1.3", "1.3.2", "2.0"])
    parser.add_argument("--propagation", choices=["current", "on", "off"], default="current")
    args = parser.parse_args()
    root = Path(flag_probe.ROOT)
    base = split_command_line(flag_probe.base_cmd(UNIT))
    compiler_index = next(i for i, arg in enumerate(base) if Path(arg).name == "mwcceppc.exe")
    for version in args.versions:
        compiler = root / "build/compilers/GC" / version / "mwcceppc.exe"
        if not compiler.is_file():
            parser.error(f"compiler unavailable: {compiler}")
        directory = Path(flag_probe.SCRATCH) / f"tricky_compiler_{version}_{args.propagation}"
        directory.mkdir(parents=True, exist_ok=True)
        source = directory / "probe.c"
        source.write_text(SOURCE, encoding="ascii")
        command = base.copy()
        command[compiler_index] = str(compiler)
        command = [arg for arg in command if arg != "-MMD"]
        command[command.index("-c") + 1] = str(source)
        command[command.index("-o") + 1] = str(directory)
        if args.propagation != "current":
            command.extend(["-opt", "propagation" if args.propagation == "on" else "nopropagation"])
        subprocess.run(command, cwd=root, check=True, timeout=30)
        obj = source.with_suffix(".o")
        print(f"\nGC/{version}: {obj}")
        for name in FUNCTIONS:
            print(name)
            for line in strucdiff.text_lines(str(obj), name):
                print("  " + line)


if __name__ == "__main__":
    main()
