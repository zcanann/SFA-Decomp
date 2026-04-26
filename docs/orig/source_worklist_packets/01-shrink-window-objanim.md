# Retail Source Boundary Packet: `objanim.c`

## Summary
- action: `shrink-window`
- confidence: `medium`
- suggested path: `main/objanim.c`
- split status: `single-split`
- retail bundles: `4`
- current seed: `0x8002EB54-0x80030688` size=`0x1B34`
- debug target size: `0x3A8`
- fit status: `seed-too-wide`
- suggested window: `0x8002EB54-0x8002F50C` size=`0x9B8` delta=`+0x610` xref_coverage=`2/3`
- suggested overlaps: `main/objanim.c`
- retail labels: `setBlendMove`
- xref count: `3`

## Why
- Seed is wider than the debug split size; the best compact candidate is `0x8002EB54-0x8002F50C`.

## EN Xref Functions
- `ObjAnim_SetBlendMove@0x8002EB54-0x8002ED18`
- `Object_ObjAnimSetMove@0x8002F23C-0x8002F50C`
- `ObjAnim_SetCurrentMove@0x80030334-0x80030688`

## Current Seed Functions
- `ObjAnim_SetBlendMove@0x8002EB54-0x8002ED18` size=`0x1C4`
- `Object_ObjAnimSetPrimaryBlendMove@0x8002ED18-0x8002ED6C` size=`0x54`
- `Object_ObjAnimSetSecondaryBlendMove@0x8002ED6C-0x8002EDC0` size=`0x54`
- `Object_ObjAnimAdvanceMove@0x8002EDC0-0x8002F20C` size=`0x44C`
- `Object_ObjAnimSetMoveProgress@0x8002F20C-0x8002F23C` size=`0x30`
- `Object_ObjAnimSetMove@0x8002F23C-0x8002F50C` size=`0x2D0`
- `ObjAnim_GetCurrentEventCountdown@0x8002F50C-0x8002F52C` size=`0x20`
- `ObjAnim_WriteStateWord@0x8002F52C-0x8002F574` size=`0x48`
- `ObjAnim_SetCurrentEventStepFrames@0x8002F574-0x8002F5D4` size=`0x60`
- `ObjAnim_SampleRootCurvePhase@0x8002F5D4-0x8002FA48` size=`0x474`
- `ObjAnim_AdvanceCurrentMove@0x8002FA48-0x80030304` size=`0x8BC`
- `ObjAnim_SetMoveProgress@0x80030304-0x80030334` size=`0x30`
- `ObjAnim_SetCurrentMove@0x80030334-0x80030688` size=`0x354`

## Suggested Inspection Window
- `ObjAnim_SetBlendMove@0x8002EB54-0x8002ED18` size=`0x1C4`
- `Object_ObjAnimSetPrimaryBlendMove@0x8002ED18-0x8002ED6C` size=`0x54`
- `Object_ObjAnimSetSecondaryBlendMove@0x8002ED6C-0x8002EDC0` size=`0x54`
- `Object_ObjAnimAdvanceMove@0x8002EDC0-0x8002F20C` size=`0x44C`
- `Object_ObjAnimSetMoveProgress@0x8002F20C-0x8002F23C` size=`0x30`
- `Object_ObjAnimSetMove@0x8002F23C-0x8002F50C` size=`0x2D0`

## Corridor Context
- previous corridor: none
- next corridor: `objhits.c`
- debug neighbors before: `SKNControl.c`, `objects.c`
- debug neighbors after: `objhits.c`, `objlib.c`

## Recommended Next Steps
- Trim the current seed around the retail-xref functions before materializing a file boundary.
- Prefer the compact suggested window as the first hypothesis, then validate surrounding rodata and call patterns.
