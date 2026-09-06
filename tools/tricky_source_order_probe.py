"""Probe Tricky source order versus MWCC deferred emission without editing the TU.

Function definitions become declarations in their original positions, then their
bodies are appended in forward or reverse order. This intentionally leaves data
definitions fixed: a good function-order result still requires a separate data
ownership audit before adopting the transformed source.
"""

import argparse
import re
import subprocess
from pathlib import Path

from elftools.elf.elffile import ELFFile

import brute_match
import flag_probe
import fwdsub_scan
from compiler_command import split_command_line


UNIT = "main/dlls/objects/196_Tricky/tricky"
SOURCE = Path(flag_probe.ROOT) / "src/dlls/objects/196_Tricky/tricky.c"
DIAGNOSTICS = (
    ("sTrickyInWaterMessage", "static char", '"in water\\n"'),
    ("sTrickyOutOfWaterMessage", "static char", '"out of water\\n"'),
    ("sTrickyShouldNeverStopCirclingError", "const char", '"error tricky should never stop when circling\\n"'),
)


def literal_diagnostics(source, names):
    for name, declaration, literal in DIAGNOSTICS:
        if name not in names:
            continue
        source = source.replace(f"extern const char {name}[];", "")
        source = source.replace(f"{declaration} {name}[] = {literal};", "")
        source = source.replace(name, literal)
    return source


def reorder(source, reverse, inline_placement="keep"):
    if inline_placement not in ("keep", "first", "last"):
        raise ValueError(f"invalid inline placement: {inline_placement}")
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
    bodies = list(reversed(functions)) if reverse else functions
    if inline_placement != "keep":
        inline_bodies = [
            item for item in bodies
            if re.search(r"\binline\b", source[item[0]:item[1]])
        ]
        ordinary_bodies = [item for item in bodies if item not in inline_bodies]
        bodies = (inline_bodies + ordinary_bodies if inline_placement == "first"
                  else ordinary_bodies + inline_bodies)
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


def compile_command(base, source, directory, deferred=False, auto_inline="current"):
    if auto_inline not in ("current", "on", "off"):
        raise ValueError(f"invalid automatic inlining policy: {auto_inline}")
    command = [arg for arg in base if arg != "-MMD"]
    command[command.index("-c") + 1] = str(source)
    command[command.index("-o") + 1] = str(directory)
    if deferred:
        command.extend(["-inline", "deferred"])
    if auto_inline != "current":
        command.extend(["-inline", "auto" if auto_inline == "on" else "noauto"])
    return command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reverse", action="store_true")
    parser.add_argument("--deferred", action="store_true")
    parser.add_argument("--auto-inline", choices=["current", "on", "off"], default="current",
                        help="Override automatic inlining independently of deferred emission")
    parser.add_argument("--literal-diagnostics", action="store_true")
    parser.add_argument("--literal-diagnostic", action="append", default=[],
                        choices=[item[0] for item in DIAGNOSTICS],
                        help="Inline only selected diagnostic strings; repeat to select more")
    parser.add_argument("--inline-placement", choices=["keep", "first", "last"], default="keep",
                        help="Move explicit inline definitions without changing ordinary function order")
    args = parser.parse_args()
    tag = f"tricky_order_{int(args.reverse)}_{int(args.deferred)}_{int(args.literal_diagnostics)}"
    if args.inline_placement != "keep":
        tag += f"_inline_{args.inline_placement}"
    if args.auto_inline != "current":
        tag += f"_auto_{args.auto_inline}"
    selected_diagnostics = set(args.literal_diagnostic)
    if args.literal_diagnostics:
        selected_diagnostics.update(item[0] for item in DIAGNOSTICS)
    elif selected_diagnostics:
        tag += "_diag_" + "".join(str(i) for i, item in enumerate(DIAGNOSTICS)
                                  if item[0] in selected_diagnostics)
    directory = Path(flag_probe.SCRATCH) / tag
    directory.mkdir(parents=True, exist_ok=True)
    source = directory / "tricky.c"
    text = literal_diagnostics(SOURCE.read_text(), selected_diagnostics)
    source.write_text(reorder(text, args.reverse, args.inline_placement), encoding="ascii")
    command = compile_command(
        split_command_line(flag_probe.base_cmd(UNIT)),
        source, directory, args.deferred, args.auto_inline,
    )
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
