# Retail Constructor Packets

This pass bridges the gap between the retail DOL vtable scan and actual exploratory split work.

`dol_vtables.py --stores-only` already proves when a short function-pointer table is written into an object-like field. What it did not do was turn that evidence into a ready packet/stub a recovery agent can open like a makeshift source file.

## Tool

- `python tools/orig/constructor_packets.py`
  - Converts store-backed retail EN vtable/callback-table candidates into constructor packets.
  - Cross-links the constructor-like store, the table slots, nearby retail string xrefs, and the current EN split coverage when any exists.
  - Can materialize non-built packet stubs under `src/main/unknown/constructors/`.

## Why This Helps

- It gives class-hierarchy work a real file foothold instead of leaving the vtable address in a note.
- It keeps the constructor function and its candidate methods together in one packet.
- It surfaces the exact object-field store offset, which is often the quickest way to tell "primary vtable at `+0`" from "embedded callback bundle at some large state offset".
- It produces non-built source packets immediately, which fits the current recovery phase better than waiting for perfect names.

## Current Packets

- `fn_80136CE4`
  - strongest current primary-class target
  - retail table `0x8031ABF4`, loaded as `0x8031ABF8`
  - store to `r30+0x0`
  - 4 method slots
  - materialized as [ctor_80136CE4_vtable.c](/C:/Projects/SFA-Decomp/src/main/unknown/constructors/ctor_80136CE4_vtable.c)
- `fn_80140340`
  - likely embedded callback/state table rather than a primary vtable
  - retail table `0x8031E614`
  - store to `r30+0x730`
  - 9 method slots
  - materialized as [ctor_80140340_callback_table.c](/C:/Projects/SFA-Decomp/src/main/unknown/constructors/ctor_80140340_callback_table.c)

## Practical Use

- summary:
  - `python tools/orig/constructor_packets.py`
- one constructor in detail:
  - `python tools/orig/constructor_packets.py --search 80136CE4`
  - `python tools/orig/constructor_packets.py --search 80140340`
- CSV for notes/spreadsheets:
  - `python tools/orig/constructor_packets.py --format csv`
- refresh the current packet stubs:
  - `python tools/orig/constructor_packets.py --materialize-top 2`

## Suggested Use

1. Start with `fn_80136CE4` because the store lands at offset `0`.
2. Open the packet stub under `src/main/unknown/constructors/`.
3. Inspect the constructor and its slot methods together before deciding whether the boundary belongs in `src/main`, a DLL file, or a future class packet.
4. Use the `fn_80140340` packet as the contrasting case for large embedded callback bundles.
