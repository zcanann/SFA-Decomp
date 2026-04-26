# Retail Source Boundary Packet: `SHthorntail.c`

## Summary
- action: `corridor-packet`
- confidence: `medium`
- suggested path: `dll/SH/SHthorntail.c`
- split status: `single-split`
- retail bundles: `4`
- current seed: `0x801D5174-0x801D550C` size=`0x398`
- debug target size: `0x3B8`
- fit status: `seed-near-fit`
- suggested window: `0x801D5174-0x801D550C` size=`0x398` delta=`-0x20` xref_coverage=`1/1`
- suggested overlaps: `main/dll/SH/dll_1E8.c`
- xref count: `1`

## Why
- Suggested window overlaps existing split owners `main/dll/SH/dll_1E8.c`; treat this as an ownership packet instead of a clean boundary move.

## EN Xref Functions
- `SHthorntail_updateState@0x801D5174-0x801D550C`

## Current Seed Functions
- `SHthorntail_updateState@0x801D5174-0x801D550C` size=`0x398`

## Suggested Inspection Window
- `SHthorntail_updateState@0x801D5174-0x801D550C` size=`0x398`

## Corridor Context
- previous corridor: `DIMbosstonsil.c`, `DIMbossspit.c`, `DFcradle.c`, `DFpulley.c`, `DFbarrel.c`, ... (+18 more)
- next corridor: `SHroot.c`, `SClevelcontrol.c`, `SClightfoot.c`, `SCchieflightfoot.c`, `SClantern.c`, ... (+106 more)
- debug neighbors before: `lily.c`, `dll_1E8.c`
- debug neighbors after: `SHroot.c`, `dll_1EC.c`

## Recommended Next Steps
- Work the whole corridor packet instead of asserting a narrow final boundary immediately.
- Use the listed gap neighbors to decide whether this source should become one file or part of a larger missing cluster.
