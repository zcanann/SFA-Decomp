# MWCC GC/1.3, GC/1.3.2, and GC/2.0: measured differences

Measured on September 6, 2026. The unchanged-source comparison uses staging
`30cb240500a6898f79bf0272f60f9771168034ae`, targeting EN v1.0 (`GSAE01`).
Subsequent source matches are recorded in [the cleanup log](compiler_gc13_cleanup.md).

GC/1.3 can recover real matches. GC/1.3.2 is a separate candidate: several
relevant changes were already present by 1.3.2. These results compare the local
compiler executables, controlled C fixtures, and complete SFA translation
units. They are not an exhaustive vendor changelog or a reconstruction of
Rare's build system.

## Identities and defaults

Dates below are the executables' own runtime build stamps, corroborated by
their PE timestamps. They are not independently established release dates.

| Package | Internal compiler version | Built | Default plain `char` | `__MWERKS__` |
| --- | --- | --- | --- | --- |
| GC/1.3 | 2.4.2 build 53 | 2002-01-10 | unsigned | 0x2406 |
| GC/1.3.2 | 2.4.2 build 81 | 2002-05-07 | signed | 0x2407 |
| GC/2.0 | 2.4.7 build 92 | 2002-09-16 | signed | 0x2407 |

Package version, internal compiler version, and preprocessor version are
different identifiers. `__MWERKS__` cannot distinguish these 1.3.2 and 2.0
binaries. The September timestamp supports the timing objection to this
particular 2.0 executable; it does not date an unknown earlier prerelease.

SHA-256 identities of `mwcceppc.exe`:

```text
GC/1.3    4e502c38465500d4fda8d966b268151a6c74c730508e3d9b7efd23d1a6083715
GC/1.3.2  7cbae0a5bd81e07d7fa8975bbc4e969b5dea265cc29c5ee6bae0453a6e25f225
GC/2.0    b79ee3e358fe18d7b492c3400169efc1a9bc5dff1a120dcb025f7869ab772022
```

Public `-help all` output for 1.3.2 and 2.0 differs only in its version/date
banner. The only additional help-text change from 1.3 is the signed-char
default. This establishes option-text continuity, not equivalent behavior.

The package's `build/compilers/info.txt` describes GC/1.3.2r as an Animal
Crossing rodata patch. It has the same build number/date as 1.3.2 and only
52 changed executable bytes, all in `.text`; every other section is identical.
It is not evidence for an independent general release.

## Controlled code-generation differences

The fixture uses Gekko, PowerPC alignment, integer enums, hardware FP,
`-O4,p -inline auto -opt nopeephole,noschedule`, FP contraction on, and C++
exceptions/RTTI off. `u32` is `unsigned long`, as in the game. Plain-char
signedness is deliberately left at the compiler default in this fixture.

| Expression or behavior | GC/1.3 | GC/1.3.2 | GC/2.0 |
| --- | --- | --- | --- |
| Return a plain `char` load | `lbz` | `lbz; extsb` | `lbz; extsb` |
| `*p |= 0x10000` on `u32*` | `lis; or` | `oris` | `oris` |
| `*p |= 0x10000u` | `oris` | `oris` | `oris` |
| `*p &= ~0x20` | `li -33; and` | `rlwinm` | `rlwinm` |
| `*p &= ~0x20u` | `rlwinm` | `rlwinm` | `rlwinm` |
| Known callee through incompatible function-pointer cast | indirect call | indirect call | direct call |
| `__OPTIMIZE__` under these flags | absent | absent | 4 |
| `__TARGET_CPU__` | absent | absent | `"PPCGEKKO"` |

The cast control declares `extern int callee(int)` and calls it through
`((int (*)(short))callee)(x)`. It deliberately uses an incompatible function
type to distinguish compiler behavior; it is not a recommended source form.
Recovering real prototypes is preferable to preserving cast workarounds.

Literal types matter even when every stored runtime value is unchanged.
Likewise, changing compiler-defined macros can change header expansion before
optimization begins. The game profile already specifies `-char signed`.

The actual game code supplies two further discriminators:

- `gameUiLoadResources` retains three pointer reloads under 1.3, matching
  retail. Newer compilers remove them: 884 bytes versus retail's 896. A simpler
  store/reload fixture is unchanged across versions, so this is context
  dependent, not a universal pointer-forwarding rule.
- Pushable and SHthorntail retain retail helper-call topology with 1.3.
  Newer compilers inline additional helpers. Disabling all automatic inlining
  introduces other calls absent from retail; it does not reproduce the same
  selective behavior. The earlier controls are in
  [the migration audit](compiler_gc13_migration.md).

## Comparing the executables directly

The installed objdiff rejects these stripped x86 PE files with
`Unknown file magic`; all four have zero COFF symbols. Objdiff is used on their
generated PowerPC ELF objects instead.

For the compiler executables, Capstone x86 disassembly and PE base relocations
support a structural comparison. A heuristic inventory starts regions at
observed direct-call targets. Normalization masks PE absolute relocations and
external relative call/jump destinations, preserving opcodes, registers,
other immediates, and local control flow.

Two routines already identified in the repository's Tricky backend tracer
have identical normalized regions across the three compiler versions:

| Routine | GC/1.3 RVA | GC/1.3.2 RVA | GC/2.0 RVA | Region bytes |
| --- | --- | --- | --- | ---: |
| GPR graph simplification | 0x107070 | 0x107B50 | 0x108A20 | 896 |
| GPR rewrite | 0x106E20 | 0x107900 | 0x1087D0 | 592 |

Region lengths include alignment before the next observed direct-call target.
Masked addresses do not prove equivalent globals or callees. These two matches
also do not establish that the entire allocator or its policy data is unchanged.
They do show why a register difference should not automatically be attributed
to a rewritten allocator: earlier expression folding, inlining, or forwarding
can change its input graph.

## Same-source SFA controls

Each complete TU was built from the same current source with each compiler,
using its actual Ninja command and existing postprocessors. All compilations
succeeded. Retail reference objects were refreshed by the strict build before
generating the reports.

| Comparison | GC/1.3 | GC/1.3.2 | GC/2.0 |
| --- | ---: | ---: | ---: |
| `gameUiLoadResources` function fuzzy | **100%** | 98.66071% | 98.66071% |
| Game UI TU fuzzy | 99.89041% | 99.83428% | 99.83428% |
| Pushable TU fuzzy | **100%** | 96.30786% | 96.30786% |
| SHthorntail TU fuzzy | **100%** | 83.81869% | 83.81869% |
| Tricky TU fuzzy | **100%** | 71.9798% | 71.9798% |

For these four TUs, 1.3.2, 1.3.2r, and 2.0 emit byte-identical `.text`.
That is a sample result, not universal compiler equivalence. Their GC/1.3
exact-function counts are 109/118, 18/18, 14/14, and 89/89 respectively;
assigned data is exact throughout.

This source had already been adjusted under 1.3. Its aggregate score is not
an unbiased provenance test. Retail reloads and call topology are stronger
independent evidence. Conversely, the original broad migration lost 90 exact
functions on then-current source, as recorded in
[the impact audit](compiler_gc13_impact.md). Source accumulated under 2.0
can need cleanup before the older compiler helps.

The subsequent DIMLavaSmas, Wisp, and three Player matches demonstrate that
cleanup directly: ordinary masks and compound flag updates recover exact
retail code with 1.3. The same new source is not exact with 2.0. See
[the per-TU controls and validation](compiler_gc13_cleanup.md).

## Artifacts and further work

Local measurement artifacts are under the ignored `build/mwcc-comparison/`:
`compiler-metadata.json`, `compiler-code-regions.json`, `source-manifest.json`,
`probes.c`, version/help diffs, allocator disassemblies, and the `probes/` and
`units/` directories with commands, logs, objects, and reports. They are local
audit outputs, not checked-in dependencies. Compiler identities, expressions,
profiles, and results are recorded above so the comparisons can be repeated.

Prioritize missing reloads, selective inlining, casted calls, and mask literal
types when revisiting old residuals. Do not automatically carry conclusions
from a GC/2.0-only source or flag sweep into GC/1.3. SDK and middleware compiler
provenance remains separate from the evidence for the game's own code.
