# Retail Source Boundary Packet: `expgfx.c`

## Summary
- action: `corridor-packet`
- confidence: `medium`
- suggested path: `dll/expgfx.c`
- split status: `single-split`
- retail bundles: `4`
- current seed: `0x8009DDEC-0x8009FCDC` size=`0x1EF0`
- xref count: `4`

## Why
- Retail seed is best treated as one packet inside a debug-side source corridor containing `objlib.c`, `objprint.c`, `objprint_dolphin.c`, `pi_dolphin.c`, `rcp_dolphin.c`.

## EN Xref Functions
- `expgfx_addToTable@0x8009DDEC-0x8009DF0C`
- `expgfx_addremove@0x8009F2CC-0x8009FCDC`

## Current Seed Functions
- `expgfx_addToTable@0x8009DDEC-0x8009DF0C` size=`0x120`
- `expgfx_updateSourceFrameFlags@0x8009DF0C-0x8009E004` size=`0xF8`
- `expgfx_func0C@0x8009E004-0x8009E024` size=`0x20`
- `expgfx_func0B@0x8009E024-0x8009E028` size=`0x4`
- `expgfx_func0A@0x8009E028-0x8009E02C` size=`0x4`
- `expgfx_func09@0x8009E02C-0x8009E034` size=`0x8`
- `expgfx_renderSourcePools@0x8009E034-0x8009E13C` size=`0x108`
- `drawGlow@0x8009E13C-0x8009ECE4` size=`0xBA8`
- `renderParticles@0x8009ECE4-0x8009EEB8` size=`0x1D4`
- `expgfx_func08@0x8009EEB8-0x8009EED8` size=`0x20`
- `expgfx_free@0x8009EED8-0x8009EFDC` size=`0x104`
- `expgfx_resetAllPools@0x8009EFDC-0x8009F1AC` size=`0x1D0`
- `expgfx_updateFrameState@0x8009F1AC-0x8009F2CC` size=`0x120`
- `expgfx_addremove@0x8009F2CC-0x8009FCDC` size=`0xA10`

## Suggested Inspection Window
- `expgfx_addToTable@0x8009DDEC-0x8009DF0C` size=`0x120`
- `expgfx_updateSourceFrameFlags@0x8009DF0C-0x8009E004` size=`0xF8`
- `expgfx_func0C@0x8009E004-0x8009E024` size=`0x20`
- `expgfx_func0B@0x8009E024-0x8009E028` size=`0x4`
- `expgfx_func0A@0x8009E028-0x8009E02C` size=`0x4`
- `expgfx_func09@0x8009E02C-0x8009E034` size=`0x8`
- `expgfx_renderSourcePools@0x8009E034-0x8009E13C` size=`0x108`
- `drawGlow@0x8009E13C-0x8009ECE4` size=`0xBA8`
- `renderParticles@0x8009ECE4-0x8009EEB8` size=`0x1D4`
- `expgfx_func08@0x8009EEB8-0x8009EED8` size=`0x20`
- `expgfx_free@0x8009EED8-0x8009EFDC` size=`0x104`
- `expgfx_resetAllPools@0x8009EFDC-0x8009F1AC` size=`0x1D0`
- `expgfx_updateFrameState@0x8009F1AC-0x8009F2CC` size=`0x120`
- `expgfx_addremove@0x8009F2CC-0x8009FCDC` size=`0xA10`

## Corridor Context
- previous corridor: `objlib.c`, `objprint.c`, `objprint_dolphin.c`, `pi_dolphin.c`, `rcp_dolphin.c`, ... (+11 more)
- next corridor: `modgfx.c`, `modelfx.c`, `dim_partfx.c`, `df_partfx.c`, `objfsa.c`, ... (+117 more)

## Recommended Next Steps
- Work the whole corridor packet instead of asserting a narrow final boundary immediately.
- Use the listed gap neighbors to decide whether this source should become one file or part of a larger missing cluster.
