"""Probe Tricky source order versus MWCC deferred emission without editing the TU.

Function definitions become declarations in their original positions, then their
bodies are appended in forward or reverse order. This intentionally leaves data
definitions fixed: a good function-order result still requires a separate data
ownership audit before adopting the transformed source.
"""

import argparse
import shlex
import subprocess
from pathlib import Path

from elftools.elf.elffile import ELFFile

import brute_match
import flag_probe
import fwdsub_scan


UNIT = "main/dlls/objects/196_Tricky/tricky"
SOURCE = Path(flag_probe.ROOT) / "src/dlls/objects/196_Tricky/tricky.c"


def reorder(source, reverse):
    functions = []
    for name, opening, closing in fwdsub_scan.find_functions(fwdsub_scan.strip_comments(source)):
        assert brute_match.find_function_body(source, name) == (opening, closing), name
        name_start = source.rfind(name, 0, opening)
        start = source.rfind("\n", 0, name_start) + 1
        functions.append((start, opening, closing + 1, name))
    declarations = []
    cursor = 0
    for start, opening, end, name in functions:
        assert start >= cursor, name
        declarations.extend([source[cursor:start], source[start:opening].rstrip() + ";\n"])
        cursor = end
    declarations.append(source[cursor:])
    bodies = reversed(functions) if reverse else functions
    return "".join(declarations) + "\n\n" + "\n\n".join(source[a:c] for a, _, c, _ in bodies)


def layout(path):
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        index = elf.get_section_index(".text")
        functions = sorted(
            (s["st_value"], s.name, s["st_size"])
            for s in elf.get_section_by_name(".symtab").iter_symbols()
            if s["st_shndx"] == index and s["st_info"]["type"] == "STT_FUNC"
        )
        sections = {name: elf.get_section_by_name(name).data() for name in [".text", ".data", ".sdata2"]}
        return functions, sections


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reverse", action="store_true")
    parser.add_argument("--deferred", action="store_true")
    parser.add_argument("--literal-diagnostics", action="store_true")
    args = parser.parse_args()
    tag = f"tricky_order_{int(args.reverse)}_{int(args.deferred)}_{int(args.literal_diagnostics)}"
    directory = Path(flag_probe.SCRATCH) / tag
    directory.mkdir(parents=True, exist_ok=True)
    source = directory / "tricky.c"
    text = SOURCE.read_text()
    if args.literal_diagnostics:
        text = text.replace("extern const char sTrickyShouldNeverStopCirclingError[];", "")
        for name, declaration, literal in [
            ("sTrickyInWaterMessage", "static char", '"in water\\n"'),
            ("sTrickyOutOfWaterMessage", "static char", '"out of water\\n"'),
            ("sTrickyShouldNeverStopCirclingError", "const char", '"error tricky should never stop when circling\\n"'),
        ]:
            text = text.replace(f"{declaration} {name}[] = {literal};", "")
            text = text.replace(name, literal)
    source.write_text(reorder(text, args.reverse), encoding="ascii")
    command = shlex.split(flag_probe.base_cmd(UNIT).replace("\\", "/"))
    command = [arg for arg in command if arg != "-MMD"]
    command[command.index("-c") + 1] = str(source)
    command[command.index("-o") + 1] = str(directory)
    if args.deferred:
        command.extend(["-inline", "noauto,deferred"])
    subprocess.run(command, cwd=flag_probe.ROOT, check=True, timeout=30)
    obj = source.with_suffix(".o")
    scores, error = flag_probe.score(UNIT, str(obj))
    if error:
        raise RuntimeError(error)
    print("text fuzzy", scores[0])
    print("nonexact", {name: value for name, value in scores[1].items() if value < 100})
    target = Path(flag_probe.ROOT) / flag_probe.UNITS[UNIT]["target_path"]
    target_functions, target_sections = layout(target)
    functions, sections = layout(obj)
    print("function offsets/names/sizes identical:", functions == target_functions)
    for name, data in sections.items():
        print(name, "bytes", len(data), "target", len(target_sections[name]),
              "raw equal", data == target_sections[name])
    print("sdata2 prefix", sections[".sdata2"][:48].hex())
    print("object", obj)


if __name__ == "__main__":
    main()
