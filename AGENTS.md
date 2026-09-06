# AGENTS.md - SFA-Decomp Runbook

> **Active compiler experiment:** All MWCC C/C++ units now inherit GC/1.3 from
> `config.compiler_version`, with no library or per-unit MWCC version overrides.
> The user excluded the ProDG decompressor (`main/zlb.c`) from this migration;
> keep its existing ProDG toolchain. The ten older GC/1.2.5 math units are included.
> Existing optimization profiles remain; the linker independently stays GC/1.3.2.
> Source matching may regress during this experiment, but both `ninja all_source`
> and the strict retail checksum target must pass before pushing. Mark regressed
> units `NonMatching` so the matching link uses their retail objects while
> `all_source` continues compiling their C/C++. Do not restore compiler exceptions,
> change the expected checksum, or disable the check to make the build green.

> **Integration workflow (effective 2026-07-29):** High-frequency decomp commits land on the
> permanent `staging` branch, not directly on `main`. Fetch before starting, check out
> `origin/staging`, and rebase local unpushed work onto the fresh remote staging tip before every
> push. Never resolve a rebase by clobbering with `--theirs`; abort and re-derive on conflict.
>
> A maintainer or bot performs one **normal merge commit** from `staging` to `main` per UTC day.
> This preserves the useful per-change history while causing the main Actions build to run once
> for the batch. After that merge is published, fast-forward `staging` to the new `main` merge
> commit before reopening it for work; do not rotate or date the staging branch. If commits land
> directly on `main`, reconcile them into `staging` without dropping either side before the next
> staging push. Larger coherent PRs remain welcome, but `staging` is the default low-overhead
> landing path.

> **Automation note (resolved 2026-06-18):** JackPriceBurns paused the loop because it
> was re-pushing a stale patch series (cherry-pick with `--theirs` conflict resolution
> reverted other contributors' fixes) and only gated on the 30s strict-hash target, so
> it never saw `all_source` breaks (dup `posPtr`, `fn_802ABFBC` mismatch). Both are
> fixed and `main` is green again. Resumed by zcanann with corrected discipline: every
> push **rebases onto the fresh active remote integration branch**, **never
> `--theirs`-clobbers** (abort + re-derive on conflict), and **gates on
> `ninja all_source` exiting 0** — not just the match target.

Keep this light. The project is still in the "recover the game" phase, not the "polish an already-understood decomp" phase.

## Target
- Active target version in this repo is `EN v1.0` (`GSAE01`).
- `orig/` may contain EN, PAL, and JP artifacts. Use them for cross-checking only.
- `resources/ghidra-decomp-4-12-2026/` contains the raw EN v1.0 Ghidra decomp with no code analysis. Use it for basic code structure only.
- `resources/DolphinSymbolExport_GSAE01.txt` contains the active EN symbol export based on Dolphin Signature analysis. This is good for SDK matching, but the addresses need to be translated against the current `config/GSAE01/symbols.txt` anchors before using them for splits.
- Other `resources/*` content should also be treated as rough shape data, not analysis.
- `reference_projects/*` may exist in some checkouts to mine patterns, especially SDK code and common Nintendo/GameCube layouts. Do not edit anything in this folder, as it is reference code from other game decompilation efforts. Known donors: `marioparty4` (2002, closest-era Nintendo title), `tww` (2002–03 Wind Waker), `melee` (2001, oldest SDK baseline), `mkdd` (2003 Mario Kart DD), `pikmin2` (2004, richest Dolphin SDK coverage — `src/Dolphin/` mirrors our layout), `prime` (2002 Metroid Prime, same year as SFA).
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
- Treat provisional per-TU compiler overrides and false-set experiments as hypotheses, not
  provenance. Source accumulated under an override will usually regress when it is removed, so
  that aggregate regression does not validate the compiler choice. Require independent evidence
  such as retail call/inlining topology, symbol shape, neighboring build settings, or contemporary
  source lineage before retaining an exceptional compiler version.
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
- Use `python tools/version_progress.py <version> --write` after EN split changes when refreshing the conservative EN rev1 / JP / PAL progress configs; the tool claims only uniquely anchored text units and leaves uncertain code and data in full-DOL autogenerated report units.
- Use `python tools/orig/source_recovery.py` when `main.dol` source-tagged strings may give EN file/function anchors for naming or splits.
- Use `python tools/orig/source_boundaries.py` when you need those retail EN source tags turned into concrete current EN work windows and split coverage status before planning a first-pass source skeleton, including cross-bundle nearby-string context and low-confidence indirect neighborhoods for no-direct-xref tags like `n_attractmode.c`.
- Use `python tools/orig/source_skeleton.py` when retail source-tagged xrefs need to be grouped into current EN address islands so you can plan first-pass source skeletons or split windows instead of treating each clue in isolation.
- Use `python tools/orig/source_corridors.py` when a retail-backed EN span needs debug-side file-size or short source-order context so you can tell whether the current seed is too small, too wide, or sitting next to one obvious missing source file.
- Use `python tools/orig/source_windows.py` when a retail-backed EN span also has an exact debug-side split and you want ranked current EN whole-file window candidates instead of only a seed-too-small / seed-too-wide verdict.
- Use `python tools/orig/source_gap_packets.py` when two retail-backed anchors leave one or a few plausible missing files between them and you want resolved debug-side path hints plus the current EN gap functions for immediate split planning, or `--materialize-all` to emit ready corridor briefs under `docs/orig/source_gap_packet_briefs/`.
- Use `python tools/orig/source_gap_windows.py` when a short retail-backed gap packet already names the missing files and you want estimated current EN per-file windows instead of one large anonymous gap span, or `--broad-exact-intervals` when the same anchors bound a larger exact debug interval you want projected into EN windows, or `--materialize-all` to emit ready briefs under `docs/orig/source_gap_window_briefs/`.
- Use `python tools/orig/source_layout.py` when you want one address-ordered per-file skeleton that interleaves retail-backed anchor windows with the short-gap file estimates so you can start claiming source boundaries directly, or `--broad-exact-layout` when you want that same layout view to include larger exact-debug corridor windows, or `--materialize-all` to emit ready layout briefs under `docs/orig/source_layout_briefs/`.
- Use `python tools/orig/source_functions.py` when you want a tighter report of retail-labeled function candidates such as `setBlendMove` / `Init` with their current EN xref clusters.
- Use `python tools/orig/source_worklist.py` when you want one prioritized queue of retail-backed boundary jobs, or `--materialize-all` to emit ready markdown packets under `docs/orig/source_worklist_packets/` for handoff.
- Use `python tools/orig/source_blueprints.py` when you want one address-ordered neighborhood view that merges anchor windows and short gap packets, or `--materialize-all` to emit ready neighborhood briefs under `docs/orig/source_blueprint_briefs/`.
- Use `python tools/orig/source_reference_hints.py` when retail EN evidence names a file but you want clearly-labeled reference-project path, function, DLL, or object hints without promoting them to source-truth.
- Use `python tools/sdk_import_probe.py` when testing candidate SDK source files against current EN windows by compiled size, function-count shape, or assigned-split audits before changing `splits.txt`.
- Use `python tools/sdk_dol_match.py` when reference projects also have known `splits.txt` plus `orig/*/sys/main.dol`; it compares normalized PPC instruction signatures across reference SDK windows and current EN windows, and `source-likely` results are strong candidates for retargeting or source import.
- Use `python3 tools/refcorpus/search_corpus.py --seq '<mnemonics>'` or `--asm '<regex>'` when an unfamiliar MWCC instruction shape needs real compiled-C examples. Discovery returns compact size-ranked function IDs; inspect only a selected result with `--show ID`.
- Use `python3 tools/symbol_context.py relevant --source <source> --function <symbol> --context <ctx>` when you need a compact list of types used by one function, then `python3 tools/symbol_context.py get <type> --context <ctx>` to retrieve the complete definition without broad source searches. Harness workspaces provide those target arguments automatically.
- Use `python tools/orig/source_object_packets.py` when a retail source tag needs to be tied back to current EN object/class/DLL packets or materialized into a non-built source packet under `src/main/unknown/source_packets/`.
- Use `python tools/orig/source_materialize.py` when you want to materialize retail-backed stubs under `src/` and/or export exact disc source/header artifacts to a local non-source folder.
- Use `python tools/orig/object_family_packets.py` when you want retail-backed object/DLL family packets or non-built `src/main/unknown/` boundary stubs for exploratory split planning before a real source filename is proven.
- Use `python tools/orig/object_def_packets.py` when you want retail-backed per-object exploratory stubs under `src/main/unknown/objects/`, cross-linked to class packets, DLL families, placement widths, and EN descriptor slots for rapid split planning.
- Use `python tools/orig/object_bin2_audit.py` when `OBJECTS.bin2` may clarify a shaky object boundary, inline substructure, or exploratory packet by comparing the sibling retail object-table lineage against live `OBJECTS.bin`.
- Use `python tools/orig/tab_catalog.py` when you need real retail chunk boundaries from `.tab` / `.bin` families before proposing asset splits.
- Use `python tools/xref/asset_clusters.py` when you want regenerable `src/xref/` JSON packets plus `docs/xref/` handoff briefs that link retail EN DOL source/file-string xrefs to current EN functions, `orig/files` asset families, and Rena file-slot metadata so you can cluster loader code, singleton-ish systems, or source islands before naming or splitting them.
- Use `python tools/orig/dol_vtables.py --stores-only` when hunting constructor-backed class boundaries, vtables, or callback tables in the retail DOL.
- Use `python tools/orig/constructor_packets.py` when a store-backed DOL vtable/callback-table hit should become a non-built `src/main/unknown/constructors/` packet for class-boundary or hierarchy recovery.
- Use `python tools/orig/romlist_params.py` when recovering object placement structs, param widths, or variable-length romlist families from retail data.
- Write small custom tools and scripts under the tools/ folder when the repo lacks the visibility needed to move quickly.

## Rules
- Bias toward EN `GSAE01` for addresses, sizes, and matching decisions.
- Treat TU boundaries confirmed from the retail DOL as structural ground truth. Do not split a
  confirmed TU into multiple source files for per-function cflags, pragma substitutes, match
  percentage, or convenience.
- Treat each confirmed numbered DLL folder as a real slot, not a disposable naming hint. Never
  collapse an adjacent slot merely because its functions, descriptor, or data are currently
  attributed to the wrong file; preserve both slots and re-audit the misplaced contents against
  the DOL. A multi-descriptor TU needs independent DOL evidence and is not implied by one source
  file currently defining multiple descriptors.
- Treat the generated `src/dlls/<bank>/<slot>[_<name>]/<file>.c` path as immutable source-truth.
  Rename symbols and types freely when evidence supports them, but do not rename an existing DLL
  source folder or filename. Use `python tools/regenerate_dll_scaffold.py --audit-ref <ref>` with
  `--slots <range>` when checking a suspected path change.
- Rehome DLL source one numbered slot at a time. Before moving a source into its canonical folder,
  audit the complete TU, neighbouring text/data boundaries, descriptor ownership, artificial
  fragments, and section-alignment overrides, then build it. Do not bulk-rehome DLL sources with
  path-only mechanical moves.
- Address-suffixed fragments such as `foo_80123456.c` are not acceptable once DOL evidence shows
  they belong to one TU. Merge them in retail function order, keep one TU-level compiler profile,
  and accept match regressions rather than preserving an artificial split. Only redraw a boundary
  when DOL section, pool, function-order, or source-tag evidence establishes a different real TU.
- End an object DLL TU with its `ObjectDescriptor` definition. Do not move the descriptor earlier
  merely to reproduce post-link section order; keep the source structure plausible and leave the
  unit `NonMatching` when the reconstructed declaration order exposes a data mismatch. Conversely,
  retain a descriptor's proven earlier position when an already-exact TU and retail symbol order
  show that other TU-owned data follows it; do not reduce a 100% unit for cosmetic uniformity.
- When a descriptor symbol provably includes data beyond its advertised callback count, model the
  complete symbol as an object-descriptor-plus-tail layout. Keep unexplained tail words opaque and
  size-asserted until real consumers establish their fields; do not inflate the callback type or
  assign meanings from value patterns alone.
- In an object descriptor initializer, use the function designator directly when its declared
  prototype exactly matches the slot typedef, such as `int getExtraSize(void)` for an
  `ObjectDescriptorExtraSizeCallback`. Keep an explicit callback cast when the generic descriptor
  slot intentionally stores a differently shaped function; do not cast away a real signature
  mismatch merely for visual uniformity.
- Keep a functionless DLL's proven eight-byte null resource record as two raw words. Do not widen
  it into `ResourceDescriptor` or `ObjectDescriptor` merely because the generic registry stores its
  address; give the record a unit-owned name and cast only at that registry boundary.
- Give each cleaned object DLL one canonical unit-owned header under `include/dlls/<bank>/`. Keep
  that header self-contained, put all unit-owned struct definitions and the public API there, and do
  not use one legacy aggregate header to declare adjacent DLLs. Include the canonical header first
  in its source; keep private constants in the TU.
- Keep layout assertions beside the canonical definition owned by that unit. Do not include
  neighboring object headers in a consumer solely to repeat unrelated state-size assertions; remove
  those imports and duplicate assertions when canonicalizing the owning types.
- Before promoting a local state or placement typedef into a canonical header, search the tree for
  the same type name. If another subsystem already uses that name for a different layout, choose an
  explicit object-specific name instead of exporting an ambiguous typedef or creating an include
  collision; back-apply the rename only to consumers of the recovered layout.
- Before renaming a public DLL function, descriptor, or data symbol, search both the source tree and
  the active-target symbol config for the proposed name. If another TU already owns it, keep the
  roles distinct with the evidenced source/object namespace; do not let an internal cleanup create
  a duplicate declaration, duplicate config key, or ambiguous cross-TU API.
- Prefer the canonical `GameObject` and `ObjAnimComponent` fields when they already express a
  cleaned DLL's accesses. Do not publish a unit-local object overlay that duplicates the common
  object prefix, `extra`, animation callback, or `userData` slots; retain a custom overlay only for
  evidenced class-specific storage that the canonical object record cannot represent.
- Keep an engine-owned object table or deliberately reused scratch pointer in its codegen-proven
  storage shape when a fully typed local changes MWCC register allocation. Use a narrow cast and
  canonical `offsetof` expression at each semantic dereference instead of hard-coded offsets or a
  fake object overlay; do not extend a typed pointer's lifetime across phases merely for cosmetic
  uniformity.
- Format the object TU and its unit-owned header, but keep shared consumer edits surgical. Adding a
  canonical header to a registry such as `modelEngine.c` does not authorize whole-file formatting
  or unrelated cleanup there; change only the required include, declaration, cast, or use sites
  unless that consumer TU is itself the active cleanup target.
- Use attached braces for control flow in cleaned code: `if (...) {`, `} else {`, `for (...) {`,
  `while (...) {`, and `switch (...) {`. Keep the controlled block on its own indented lines even
  when it contains one statement. Do not introduce Allman-style control-flow braces into a cleaned
  TU or preserve them merely because the surrounding imported decomp is inconsistent.
- Run `clang-format -i` on the active cleaned TU and its unit-owned canonical header, then review the
  formatting diff and require `clang-format --dry-run --Werror` to pass for both. Commit formatting
  separately from source changes so compiler and code cleanup diffs remain easy to review. Verify
  that the formatting-only commit preserves code generation. Do not format a
  shared consumer merely because the active TU adds one include or declaration there; keep those
  shared edits surgical unless that consumer is itself the cleanup target.
- For the object-DLL housekeeping pass, assign each TU cleanup to a sub-agent and keep no more than
  three sub-agents active at once. The primary agent must personally review every resulting diff,
  stale-symbol search, match report, shared-consumer edit, and generated-path audit before
  committing. Commit and push reviewed TUs one coherent slot at a time.
- When a newly evidenced housekeeping rule exposes the same purely mechanical, byte-neutral issue
  across previously reviewed object TUs, audit the complete cleaned range and land the back-apply
  as a dedicated range-audit commit rather than burying it in the current slot. Record every
  intentional exception, compare each affected object before and after, and keep non-mechanical or
  codegen-changing cases in their own TU reviews.
- Claim a cleaned TU's complete evidenced constant pool only when the source can emit it without
  duplicate named constants, invented section placement, or codegen changes. MWCC may copy a
  same-TU named `const` scalar into a second anonymous literal while leaving the named definition
  unreferenced, so source-only ownership and matching values are not enough. Keep the automatic
  gap until the original ownership model is recoverable; after any claim, verify generated section
  size, symbols, bytes, relocations, and the final DOL.
- Preserve a packed TU-owned diagnostic or string block when splitting it into unreferenced named
  `const` arrays makes MWCC migrate bytes between `.data` and `.rodata`. Give the backing block a
  semantic name and recover a typed offset view instead, then verify section sizes and contents.
- Size placement/setup structs from active-target evidence such as a direct `Obj_AllocObjectSetup`
  allocation or retail romlist width, not from the last field accessed by the TU or donor-project
  padding. Assert the proven total size as well as every recovered field offset.
- Size struct arrays from evidenced indices or explicit runtime capacity, not merely from the gap
  to the next known field. If the code caps a six-element child list and the next field is eight
  words later, model six elements plus an unknown trailing word; do not invent a seventh child to
  consume the offset.
- Consolidate contiguous, entirely unaccessed imported byte fields into one opaque byte span unless
  retail layout or a real consumer distinguishes their roles. Do not preserve separate `unkXX`
  byte scalars merely because Ghidra guessed field boundaries; conversely, keep any byte that is
  independently loaded, stored, or interpreted at a codegen-significant width as its own field.
- Size an object state from that object's allocation contract, not from every helper defined in its
  TU. If a helper is called only with another object's larger state and accesses beyond the owner's
  `getExtraSize`, model the owning state and the cross-object helper overlay as separate types,
  assert both layouts, and keep the cast explicit at the reuse boundary. A proven zero
  `getExtraSize()` owns no extra-state typedef unless independent object-owned storage is
  separately evidenced.
- Do not cast one object's state to an unrelated object's type merely because useful fields happen
  to share offsets. Recover those fields in the owning state; share a state type only when allocation
  and behavioral evidence establish a real common contract.
- When retail code provably reads or writes past an allocation or object boundary, preserve and
  document the exact access without enlarging the owning type to make the bug appear in bounds.
  Keep the allocation-backed size assertion, use an explicit byte access for the overrun, and audit
  adjacent data ownership so the source records what is actually clobbered.
- When two proven consumers interpret the same shared placement byte with different signedness and
  both views are codegen-significant, model explicit union views at the shared offset. Do not force
  one canonical signedness and scatter casts; assert both offsets and rebuild every consumer.
- Recover a placement field at the width actually loaded. If a supposed `s16` is only accessed as
  `*(u8*)&field` at the field's address, model the evidenced `u8` plus the following unknown byte;
  on the big-endian target that cast selects the first/high-order byte, not a generic "low byte."
- When a shared placement record has proven mode-specific roles at the same offsets, expose
  explicit semantic union views in the owning canonical header and use the relevant view in each
  mode or consumer. Do not preserve one misleading generic name or duplicate the record as
  competing padded structs; assert every recovered view at the shared offset.
- Include an object's canonical header at direct consumers instead of repeating hand-written
  declarations. Where a generic registry intentionally stores differently shaped descriptor
  types, use an explicit cast at that boundary rather than lying about the descriptor's type in an
  `extern`.
- In an already-exact unit, test apparently redundant predicates, casts, and integer/pointer
  launders before normalizing them. If the simpler spelling changes codegen, retain the proven
  spelling and improve the surrounding names instead; cosmetic uniformity does not justify a match
  regression.
- Do not split a multi-role local in an already-exact function solely to give each lifetime a more
  specific name without testing codegen. MWCC can assign different nonvolatile registers even when
  the lifetimes do not overlap; if the split changes codegen, retain one neutrally named local and
  let each use site supply the meaning.
- Do not delete an unused static helper or collapse a semantic enum into macros in an already-exact
  TU without comparing the raw object hash and symbol table. Even when MWCC emits no body and
  objdiff still reports every function and section exact, removing the source-position anchor can
  renumber anonymous symbols. Retain a compact documented anchor or the clearer declaration when
  the cosmetic rewrite changes object identity.
- Preserve TU-global declaration order while renaming or retyping symbols, especially mixed-width
  `.sbss` and `.sdata` objects. Objdiff can report zero-filled sections and symbol-normalized
  relocations as exact while MWCC has changed the symbols' packed offsets; inspect object symbol
  offsets and require the final DOL checksum before accepting the cleanup.
- Preserve a literal's C type when lifting it into a named macro or enum. Suffixes are semantic:
  replacing `1u` with a macro whose replacement is `1` can change the usual arithmetic conversions
  and turn a target `cmplwi` into `cmpwi`, even when the runtime values are identical. Rebuild the
  affected function after every such lift.
- Do not infer unsigned storage merely because a byte is used as a boolean. Preserve signedness
  evidenced by the exact load/compare sequence; an `s8` zero-test can require the target's sign
  extension even when negative values have no separately recovered meaning.
- Before retaining a unit-prefixed alias for an engine-wide flag, enum value, or ID, search the
  canonical engine headers. Use the shared definition when it already exists; local duplicates such
  as per-object names for `OBJECT_OBJFLAG_HITDETECT_DISABLED` obscure that multiple DLLs implement
  the same engine contract.
- When an object-family group or ID is owned by one DLL but used by other TUs, define it once in
  the owning canonical header and use that definition at every proven consumer. Do not preserve
  consumer-local aliases or raw numeric lookups for the same family contract; audit all active-target
  uses before declaring the migration complete.
- When a unit-local semantic name conflicts with the canonical name for the same engine value, audit
  every active-target consumer before choosing either name. If the combined behavior establishes a
  stronger shared meaning, correct the canonical definition and back-apply it to all consumers
  instead of preserving divergent aliases or adopting a misleading canonical name.
- Do not promote an unnamed DLL to a named object solely from a nearby debug-side source tag, an
  adjacent named slot, or behavioral resemblance. Keep a numbered namespace until retail object
  mappings, strings, symbols, or similarly direct evidence establishes the identity; recover
  semantic field, state, and helper names in the meantime.
- Once an unnamed numbered slot provably owns an address-labeled descriptor, give that descriptor a
  stable numbered symbol such as `gDll144ObjDescriptor` and update the active symbol config. Keep
  the functions in the same numbered namespace and do not treat this internal rename as evidence
  for renaming the generated source folder or filename.
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
3. Build the strict hash target with `python configure.py --matching` followed by `ninja` (if anything goes wrong, consider running `python configure.py -v GSAE01 --matching`). Always timeout ninja to 30s; plain non-matching `ninja` can stop at `main.dol` and miss the checksum target that CI runs.
4. Run objdiff and judge net progress.
5. If stuck, change angle quickly: adjacent code, data, assets, references, or tooling.
6. Commit real progress to the permanent staging branch and push to `origin/staging`. Do not push
   normal development commits directly to `main`.
7. If the process changes (ie we expect ninja to pass after a session, etc.) please update this document.

## Commit Standard
Commit when both are true:
- The repo is materially better: codegen, data, linkage, structure, or tooling improved, even if marginally.
- The result is plausible original source or materially improves the ability to recover it.

Less process is intentional. Use judgment, move fast, and avoid spending an hour proving a bad assumption.

## Ghidra Drift Playbook (add-new-function pattern)

The Ghidra-imported `dll_XXX.c` files are usually decomp'd from a different snapshot
than the v1.0 `.s` we're matching against. Symptom: the report says "1 stub" but
when you read the asm you find 3-5 stubs, and the src functions (often named
`FUN_801cXXXX`) are at addresses INSIDE the asm symbol ranges - Ghidra split
them differently than the binary did.

**Do not** try to fix the misaligned `FUN_xxx` functions in place. Compile order
matters less than you think. Instead use the **add-new-function** pattern:

1. Read `build/GSAE01/asm/main/dll/<unit>.s` and list `^\.fn` symbols + sizes.
   That is the canonical function set.
2. List the src's current function set (`grep -nE "^void|^int|^undefined" src/...`).
3. For each asm symbol missing from src, ADD a new function with that exact name
   to the bottom of the src file. The src file's existing `FUN_xxx` functions
   can stay - they're dead/unreferenced or referenced only externally.
4. Read the asm body for the new function and translate to C. Cargo-cult call
   patterns from already-matched files:
   - `(*(code *)(*(int *)lbl_XXX + offset))(args)` for vtable calls through
     SDA21 pointer-to-pointer.
   - `extern int Obj_IsObjectAlive(void* obj);` style — check `src/main/dll/*.c`
     for existing extern declarations.
   - `(double)lbl_SDA_FLOAT` for f1 args to functions that take a `double`.
   - `*(unsigned char*)(p + off)` instead of `*(char*)(p + off)` when the asm
     reads with `lbz; cmplwi` (no `extsb.`).
5. Build, check the report, commit per-function gains. Even a partial fuzzy
   match (50-90%) is real progress and unblocks the unit from "0 of N matched"
   purgatory.

For deeper structural fixes (where the asm body of one symbol corresponds to a
`FUN_xxx` source function, just renamed), see `dbbc5ba9 Restructure laser19F`:
move the `FUN_xxx` body into the right symbol with the right signature, delete
the `FUN_xxx`, drop its `.h` declaration. Keep `FUN_xxx` only if other `.c`
files extern-reference it (e.g. shrine.c calls FUN_801c4b14).

Wins seen in practice: byte-exact matches when the body lines up well, ~50-99%
fuzzy otherwise. The remaining MWCC-vs-target diffs are usually unimportant
scheduling choices (`extsb.` vs `extsb + cmplwi`, `lis r3` order vs `slwi r0`,
epilog reordering of `lwz r0` vs saved-reg restores) that we can't trivially
force from C source.

## Inline assembly

The optional joint-matrix analyzer experiment is documented in
`docs/foreign/joint_matrices.md`: build with `python3 tools/dtk_nocfa.py --test`,
then configure with `--matching --joint-matrices-nocfa`. Its local DTK patch trusts
the evidenced outer function extent; it does not establish source-language
provenance or change the assembly policy below. Default builds keep upstream DTK.

Inline `asm{}` is banned outside `src/dolphin/`. Inside SDK code, the only
exception is paired-single `psq_l` / `psq_st` when MWCC has no intrinsic and a
known-good donor or original binary proves the sequence. Do not trade plausible
C for a higher match score; a clean-C 90% match is better than an asm 100% match.

## Pragmas

Inline pragmas are banned. `#pragma` of any kind must not appear inline in `src/main/` or `src/track/`
source; pragmas may only be configured at the TU level via `configure.py` cflags.

## Cheap clean-C pre-checks

Try these one-line source rewrites first; sometimes they're enough on their own:
- `& 0xff7f` → `& ~0x80`         (often gives `rlwinm` where literal gives `andi`)
- `*(int*)p != 0` → `*(void**)p != NULL`   (signed → unsigned compare)
- `if (v <= K) return v; return K;` → `if (v > K) v = K; return v;`
  (gives `blelr` from a single value-clamp)
- For a constant reused across N consecutive stores, lift to a local:
  `f32 fz = lbl_xxx; *p1 = fz; *p2 = fz; *p3 = fz;` so MWCC CSEs across the
  stores instead of reloading.
- Swap declaration order of two `int` locals whose addresses are passed to an
  out-param function. The compiler allocates stack offsets in declaration
  order; if target wants `&objectIndex` at sp+8 and `&objectCount` at sp+0xc,
  declare objectCount first.
