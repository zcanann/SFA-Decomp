# Retail `OBJECTS.bin2` Lineage Audit

This pass answers one specific open question in the repo: whether `orig/GSAE01/files/OBJECTS.bin2` is useful recovery evidence or just another opaque leftover.

## Tool

- `python tools/orig/object_bin2_audit.py`
  - Aligns `OBJECTS.bin2` against the live `OBJECTS.bin` using the embedded 11-byte object-name field instead of reusing `OBJECTS.tab`.
  - Compares object spans, core DLL/class/map metadata, inline substructure hints, and model/sequence counts.
  - Can materialize non-built comparison packets under `src/main/unknown/object_lineage/`.

## Why This Helps

Before this pass, `OBJECTS.bin2` was acknowledged as interesting but unexplained.

The useful result is that it is not random junk:

- it preserves the same object-name order for almost the whole table
- it keeps the same DLL/class/fixed-map lineage for nearly every matched def
- only a small set of defs show structural differences, which makes them easy to target

That turns `OBJECTS.bin2` into alternate evidence for object boundaries and inline substructures, especially for the handful of defs where the live table still looks suspicious.

## High-value findings

### 1. `OBJECTS.bin2` is a real sibling object table

- exact ordered name-field matches: `1474 / 1477` defs
- unresolved exact name-field matches: `3`
  - `WC_LandingP`
  - `WarpCigar`
  - `WarpGasCyli`

This is strong evidence that `OBJECTS.bin2` is another object-def lineage, not arbitrary garbage.

### 2. Core metadata is almost perfectly stable across the matched set

Across the `1474` matched defs:

- DLL IDs are stable for `1474`
- class IDs are stable for `1474`
- fixed map IDs are stable for `1474`

That makes `OBJECTS.bin2` useful for structure recovery without forcing a second naming taxonomy.

### 3. Only a tiny slice of defs actually changes structurally

The structurally interesting set is only `15` defs:

- size deltas: `11`
- inline-field deltas: `6`
- count deltas: `2`
- unresolved name-field matches: `3`

The highest-signal current deltas are:

- `CFMainSlide`: `0xC0 -> 0x2C0`
- `CFAnimPower`: `0xA0 -> 0x1A0`
- `CFBlastedTu`: `0xA0 -> 0x160`
- `Sabre`: `0x860 -> 0x800`
- `Krystal`: `0x860 -> 0x840`
- `SH_killermu`: `0xE0 -> 0x100`

These are the best places to compare lineages before finalizing exploratory object packets or split boundaries.

### 4. Model lists diverge much more often than structural fields do

Matched defs with model-ID list deltas: `668`

That split matters:

- object taxonomy is mostly stable
- content/model linkage is not

So `OBJECTS.bin2` looks more like a sibling content lineage than a second unrelated object table.

## Materialized packet stubs

The intended workflow is:

- inspect the audit:
  - `python tools/orig/object_bin2_audit.py`
- search one def:
  - `python tools/orig/object_bin2_audit.py --search Sabre`
  - `python tools/orig/object_bin2_audit.py --search status:size-delta`
- materialize the strongest comparison packets:
  - `python tools/orig/object_bin2_audit.py --materialize-top 8`

Those packet stubs are intentionally non-built. Their job is to keep the live and `bin2` object evidence together while you decide whether a current exploratory object file is missing inline data, overgrown, or still using the wrong boundary.
