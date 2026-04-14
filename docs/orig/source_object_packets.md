# Retail Source/Object Recovery Packets

This pass fills the gap between the existing source-tag tools and the object packet tools.

`source_recovery.py` can tell us that `curves.c` or `DIMBoss.c` exists in retail EN. `object_*_packets.py` can tell us that `curve` is DLL `0x0125` or that `DIM_Boss` is object def `0x006E`. Before this tool, there was no ready-to-use bridge that kept both views together.

## Tool

- `python tools/orig/source_object_packets.py`
  - Merges retail EN source-tag strings, current EN xrefs, current EN object/class/DLL packets, and clearly-labeled reference-only path/function hints.
  - Can materialize non-built source packets under `src/main/unknown/source_packets/`.

## Why This Helps

- It turns a retail file name into a concrete split target plus the current EN object/DLL anchors around it.
- It keeps the object-family evidence attached to named retail sources instead of making you manually jump between `source_recovery.py`, `source_reference_hints.py`, `object_family_packets.py`, and `object_def_packets.py`.
- It makes it much easier to answer "is this source tag probably a real gameplay DLL, a main-system file, or just a naming lead with no object hook yet?"

## High-Value Current Packets

- `curves.c`
  - cleanest current bridge
  - retail warning string plus one EN xref
  - lands on current EN DLL `0x0125` `curve`
  - singleton class `0x002C` and singleton object def `0x0491`
- `DIMBoss.c`
  - retail source tag now lands on current EN DLL `0x01E0` `DIM_Boss`
  - immediately points at object def `0x006E`
  - keeps the current EN descriptor slot map attached
- `SHthorntail.c`
  - retail file name plus current EN DLL `0x01AD` `SH_thorntail`
  - current EN object def packet is already linked from the result
- `textblock.c`
  - especially useful because the retail `Init` label was previously just a source-name clue
  - packet now ties it to current EN DLL `0x0239` `TextBlock`
  - also surfaces the five current zero-placement object defs that still need file-boundary judgment
- `objanim.c`
  - no object-family match, which is itself useful
  - packet still locks together the retail `setBlendMove` label, the three EN xrefs, and the stable `src/main/objanim.c` target
- `expgfx.c`
  - strongest current xref density among the retail source tags
  - currently still lacks a convincing object-family match, so it stays a source-first target rather than a boundary-first one

## Materialized Packet Stubs

The current top batch was materialized with:

- `python tools/orig/source_object_packets.py --materialize-top 6`

That wrote:

- [curves.c](/C:/Projects/SFA-Decomp/src/main/unknown/source_packets/dll/curves.c)
- [expgfx.c](/C:/Projects/SFA-Decomp/src/main/unknown/source_packets/dll/expgfx.c)
- [DIMboss.c](/C:/Projects/SFA-Decomp/src/main/unknown/source_packets/dll/DIM/DIMboss.c)
- [SHthorntail.c](/C:/Projects/SFA-Decomp/src/main/unknown/source_packets/dll/SH/SHthorntail.c)
- [objanim.c](/C:/Projects/SFA-Decomp/src/main/unknown/source_packets/main/objanim.c)
- [textblock.c](/C:/Projects/SFA-Decomp/src/main/unknown/source_packets/textblock.c)

These are intentionally packet files, not source-truth. Their job is to keep the named retail source target and the current EN boundary evidence in one place.

## Practical Use

- Summary:
  - `python tools/orig/source_object_packets.py`
- One source in detail:
  - `python tools/orig/source_object_packets.py --search curves`
  - `python tools/orig/source_object_packets.py --search DIMBoss`
- Search by current EN boundary:
  - `python tools/orig/source_object_packets.py --search dll:0x0125`
  - `python tools/orig/source_object_packets.py --search def:0x006E`
- Refresh the current high-signal packet stubs:
  - `python tools/orig/source_object_packets.py --materialize-top 6`

## Current Limits

- The current EN DLL/object match is still inference, not retail truth. The tool labels it that way on purpose.
- Some retail source tags, such as `camcontrol.c` and `objHitReact.c`, still do not have a convincing current object-family bridge.
- `OBJECTS.bin2` still looks like a separate unexplained object-table lineage and remains worth a dedicated follow-up tool pass.
