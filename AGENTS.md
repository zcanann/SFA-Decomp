# AGENTS.md - SFA-Decomp Runbook

Keep this light. The project is still in the "recover the game" phase, not the "polish an already-understood decomp" phase.

## Target
- Active target version in this repo is `EN v1.0` (`GSAE01`).
- `orig/` may contain EN, PAL, and JP artifacts. Use them for cross-checking only.
- `resources/ghidra-decomp-4-12-2026/` contains the raw EN v1.0 Ghidra decomp with no code analysis. Use it for basic code structure only.
- `resources/DolphinSymbolExport_GSAE01.txt` contains the active EN symbol export based on Dolphin Signature analysis. This is good for SDK matching, but the addresses need to be translated against the current `config/GSAE01/symbols.txt` anchors before using them for splits.
- Other `resources/*` content should also be treated as rough shape data, not analysis.
- `reference_projects/*` may exist in some checkouts to mine patterns, especially SDK code and common Nintendo/GameCube layouts. Do not edit anything in this folder, as it is reference code from other game decompilation efforts.
- SDK files have already been added to this project, but they are from another game. We will need to assign our splits to use these files, update symbols, and possibly learn from `reference_projects/*` to drive our SDK files to matching.
- `reference_projects/rena-tools*` may exist in some checkouts with Rena's SFA decomp projects, and may have some information that helps.

## What Progress Looks Like
- Recover real functions, data, class boundaries, globals, vtables, and file structure.
- Improve buildability, linkage, and objdiff results.
- Make the source look more like plausible original code, not a pile of coercion hacks.
- Generate new understanding when the repo has none yet.

This repo starts from very little. Expect to do naming, struct recovery, type cleanup, file splitting, and tool building as part of normal work.

## Ground Truth
- `objdiff` is still the final measure of whether a change helped.
- Ghidra output is raw input. It will often be wrong about types, signatures, control flow details, and boundaries.
- There are no symbol maps to lean on here. Do not write the workflow as if names or section layout are already known.
- Reference projects are evidence, not truth. Match version, compiler behavior, ABI, and surrounding code before borrowing anything.

## Working Style
- Start from one promising function, object, data block, or subsystem.
- Work outward aggressively if the blocker is adjacent code, missing types, unknown globals, constructor patterns, SDK reuse, or bad file boundaries.
- Do not get trapped in local optima. If a path stops yielding structure, switch level: inspect related code, assets, rodata, strings, object layouts, SDK analogs, or write tooling.
- Prefer recovering coherent source over narrowly chasing one assembly diff while the surrounding code remains obviously wrong.
- Please try to keep the build in a functional state (ninja should compile successfully on work complete and a fresh run).

## Expected Work
- Infer function names where none exist yet.
- Recover data definitions and rodata ownership.
- Establish class and subsystem boundaries.
- Replace guessed offsets and anonymous blobs with real fields when justified.
- Identify reusable SDK or middleware code from `reference_projects/*`.
- Mine strings, assets, tables, and binary patterns when that reveals structure.
- Use `python tools/orig/source_leaks.py` when checking whether `orig/*` still preserves direct source/header names before leaning on external debug-side references.
- Use `python tools/orig/source_matrix.py` when PAL / JP / EN rev1 may strengthen or rename a weak source-tag clue before you commit to a file name or materialize a stub.
- Use `python tools/orig/source_recovery.py` when `main.dol` source-tagged strings may give EN file/function anchors for naming or splits.
- Use `python tools/orig/source_boundaries.py` when you need those retail EN source tags turned into concrete current EN work windows and split coverage status before planning a first-pass source skeleton.
- Use `python tools/orig/source_skeleton.py` when retail source-tagged xrefs need to be grouped into current EN address islands so you can plan first-pass source skeletons or split windows instead of treating each clue in isolation.
- Use `python tools/orig/source_corridors.py` when a retail-backed EN span needs debug-side file-size or short source-order context so you can tell whether the current seed is too small, too wide, or sitting next to one obvious missing source file.
- Use `python tools/orig/source_windows.py` when a retail-backed EN span also has an exact debug-side split and you want ranked current EN whole-file window candidates instead of only a seed-too-small / seed-too-wide verdict.
- Use `python tools/orig/source_gap_packets.py` when two retail-backed anchors leave one or a few plausible missing files between them and you want resolved debug-side path hints plus the current EN gap functions for immediate split planning, or `--materialize-all` to emit ready corridor briefs under `docs/orig/source_gap_packet_briefs/`.
- Use `python tools/orig/source_functions.py` when you want a tighter report of retail-labeled function candidates such as `setBlendMove` / `Init` with their current EN xref clusters.
- Use `python tools/orig/source_worklist.py` when you want one prioritized queue of retail-backed boundary jobs, or `--materialize-all` to emit ready markdown packets under `docs/orig/source_worklist_packets/` for handoff.
- Use `python tools/orig/source_blueprints.py` when you want one address-ordered neighborhood view that merges anchor windows and short gap packets, or `--materialize-all` to emit ready neighborhood briefs under `docs/orig/source_blueprint_briefs/`.
- Use `python tools/orig/source_reference_hints.py` when retail EN evidence names a file but you want clearly-labeled reference-project path, function, DLL, or object hints without promoting them to source-truth.
- Use `python tools/orig/source_object_packets.py` when a retail source tag needs to be tied back to current EN object/class/DLL packets or materialized into a non-built source packet under `src/main/unknown/source_packets/`.
- Use `python tools/orig/source_materialize.py` when you want to materialize retail-backed stubs under `src/` and/or export exact disc source/header artifacts to a local non-source folder.
- Use `python tools/orig/object_family_packets.py` when you want retail-backed object/DLL family packets or non-built `src/main/unknown/` boundary stubs for exploratory split planning before a real source filename is proven.
- Use `python tools/orig/object_def_packets.py` when you want retail-backed per-object exploratory stubs under `src/main/unknown/objects/`, cross-linked to class packets, DLL families, placement widths, and EN descriptor slots for rapid split planning.
- Use `python tools/orig/object_bin2_audit.py` when `OBJECTS.bin2` may clarify a shaky object boundary, inline substructure, or exploratory packet by comparing the sibling retail object-table lineage against live `OBJECTS.bin`.
- Use `python tools/orig/tab_catalog.py` when you need real retail chunk boundaries from `.tab` / `.bin` families before proposing asset splits.
- Use `python tools/orig/dol_vtables.py --stores-only` when hunting constructor-backed class boundaries, vtables, or callback tables in the retail DOL.
- Use `python tools/orig/constructor_packets.py` when a store-backed DOL vtable/callback-table hit should become a non-built `src/main/unknown/constructors/` packet for class-boundary or hierarchy recovery.
- Use `python tools/orig/romlist_params.py` when recovering object placement structs, param widths, or variable-length romlist families from retail data.
- Write small custom tools and scripts under the tools/ folder when the repo lacks the visibility needed to move quickly.

## Rules
- Bias toward EN `GSAE01` for addresses, sizes, and matching decisions.
- Prefer real definitions and linkage over `extern` placeholders.
- Do not hardcode addresses or invent junk `lbl_` / `fn_` names just to force progress.
- Do not commit literal recovered source/header artifacts from `orig/` into `src/`; keep them in manifests/docs or export them to a local non-source folder when needed.
- When materializing retail-backed stubs without a proven directory, keep them at `src/<basename>` instead of inventing synthetic folders.
- Do not manually force compiler-generated sections or synthesize likely-generated init/ctor/dtor glue unless there is strong evidence.
- Keep code clean. No analysis debris, commented-out experiments, or notes in the project tree.
- Use other regions to inform understanding, not to override the EN target.
- Do not paste raw Dolphin addresses straight into config. Run `python tools/dolphin_sdk_symbols.py summary` first, use the inferred address translation, then review the surrounding translated cluster manually.

## Minimal Loop
1. Pick a target with real leverage.
2. Recover the surrounding dependency cluster, not just the leaf symbol.
3. Build with `ninja` (if anything goes wrong, consider running configure.py -v GSAE01). Always timeout ninja to 30s, it will never take longer, and sometimes bad linker changes can hang forever.
4. Run objdiff and judge net progress.
5. If stuck, change angle quickly: adjacent code, data, assets, references, or tooling.
6. Commit real progress directly to the main working branch for this phase and push to main. No PR flow is required right now.
7. If the process changes (ie we expect ninja to pass after a session, etc.) please update this document.

## Commit Standard
Commit when both are true:
- The repo is materially better: codegen, data, linkage, structure, or tooling improved, even if marginally.
- The result is plausible original source or materially improves the ability to recover it.

Less process is intentional. Use judgment, move fast, and avoid spending an hour proving a bad assumption.
