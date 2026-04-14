# `orig/GSAE01/sys/main.dol` vtable-style table notes

This pass focuses on a narrower question than the existing string and file-table audits: does the retail EN DOL still expose any constructor-backed function-pointer tables that can help recover class boundaries, virtual methods, or callback structs?

## Tool

- `python tools/orig/dol_vtables.py --stores-only`
  - Scans retail EN `main.dol` data sections for short runs of text pointers.
  - Cross-checks each run against direct `lis` + `addi` / `ori` loads in text.
  - Marks tables that are subsequently written into object-like registers (`r3`, `r26`-`r31`) as constructor-style candidates.

## High-value findings

### 1. One retail table is a strong vtable-like candidate

The strongest hit is:

- table start: `0x8031ABF4`
- effective loaded address: `0x8031ABF8`
- slot count: `4`
- prefix words: `0x80111878`, `0x00000000`
- leading methods:
  - `fn_8011175C`
  - `fn_80111160`
  - `fn_8011115C`
  - `fn_801110CC`
- constructor-style store:
  - `fn_80136CE4+0x70` loads `0x8031ABF8`
  - `fn_80136CE4+0x88` stores it to `r30+0x0`

Why this matters:

- the load lands inside a short function-pointer run rather than a scalar data table
- the stored destination is object base `+0`, which is the classic place to look for a primary vtable pointer
- one zero prefix word survives immediately before the loaded address, which is consistent with C++ metadata or padding rather than a random dispatch array

This is enough to treat `fn_80136CE4` as a real constructor candidate and `0x8031ABF4` as a plausible class boundary anchor.

### 2. A second table looks like an object-resident callback bundle

The other store-backed hit is:

- table start: `0x8031E614`
- slot count: `9`
- prefix words: `0x47524F57`, `0x4C0A0000`
- leading methods all resolve back into `fn_80140340`
- constructor-style store:
  - `fn_80140340+0x30` loads `0x8031E614`
  - `fn_80140340+0x60` stores it to `r30+0x730`

This is probably not a primary vtable, but it is still useful:

- it shows a real object field that owns a function-pointer table
- it suggests `fn_80140340` is setting up a large stateful struct rather than just touching scalars
- it gives one concrete object offset, `+0x730`, to keep in mind while recovering that subsystem

### 3. The heuristic stays intentionally conservative

The tool scans 619 candidate pointer tables in the EN DOL, but only 2 are shown with `--stores-only`.

That is deliberate:

- many raw pointer runs are state tables, script dispatch arrays, or other non-class data
- the store-backed filter keeps the results small enough to inspect manually
- if someone wants broader exploration, `python tools/orig/dol_vtables.py --limit 20` will show the higher-ranked non-store-backed tables too

## Practical use

- Constructor-focused summary:
  - `python tools/orig/dol_vtables.py --stores-only`
- CSV for notes or spreadsheets:
  - `python tools/orig/dol_vtables.py --stores-only --format csv`
- Focus one subsystem:
  - `python tools/orig/dol_vtables.py --stores-only --search 80136CE4`
  - `python tools/orig/dol_vtables.py --stores-only --search 80140340`

The main value is not the raw table addresses by themselves. It is the pair of:

- one code address that appears to initialize an object
- one nearby data table that already behaves like a class or callback boundary in retail code
