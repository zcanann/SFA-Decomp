# Demo-churn x match-frontier worklist

Crosses the E3-2002 demo `sys/main.dol` churn map (README §6b) against fresh
`report.json` match truth. For a TU that is stream-identical to the demo, the demo DOL is a
second, drift-free link of the identical code: pool layout, literal values, and scheduling can
be cross-checked at the KIOSK addresses below with no drift caveat.

State when derived: `build/GSAE01/report.json` regenerated (the July 28 report was stale — it
showed 114 sub-100 TUs and 32 dead unit keys; fresh truth is **85 sub-100 TUs**, all 944 .text
TUs resolving 1:1 to splits/configure names). Census figures reconcile at 944 .text TUs / 396
zero-region by start-unit attribution / **359 strictly untouched** once boundary-spanning
regions are attributed by address overlap.

## Table A — drift-free frontier (stream-identical to demo, <100%)

No boundary-insert ambiguity on any row; zero demo-only strings attributable to these ranges
(expected by construction — a demo-only artifact implies a change region).

| Unit | fuzzy % | Status | .text size | KIOSK range | Notes |
|---|---|---|---|---|---|
| main/textrender_boxtex.c | 96.66 | NonMatching | 0x3A8 | 8001BC58-8001C000 | single fn `gameTextInitBoxTextures` |
| MSL_C/.../math_8029454c.c | 98.36 | NonMatching | 0xF4 | 80291C34-80291D28 | `mathTanf`, `log2fBitEstimate` |
| main/sincosf.c | 98.75 | NonMatching | 0x140 | 8029134C-8029148C | `mathSinCosf` |
| dlls/engine/3/3.c | 99.53 | NonMatching | 0x2038 | 800D41B0-800D61E8 | Checkpoint_* DLL, 18 fns |
| musyx/runtime/synth_seq_dispatch.c | 99.75 | NonMatching | 0x1458 | 8026BADC-8026CF34 | MusyX seq dispatch |
| MSL_C/.../exponentialsf.c | 99.78 | NonMatching | 0x77C | 802922A0-80292A1C | `powf` |
| musyx/runtime/synth_queue.c | 99.85 | NonMatching | 0x11A8 | 80269E80-8026B028 | `seqStartPlay`/`seqPause`/... |
| dlls/objects/625/625.c | 99.97 | NonMatching | 0x1C08 | 8021E164-8021FD6C | drakorhoverpad, 29 fns |

## Table B — low-drift frontier (1-2 regions, <100%)

`a`/`b` = bytes touched retail/demo side. **[X-TU]** = the touched span is a region starting in
a neighboring TU; the rest of the TU is stream-identical.

| Unit | fuzzy % | .text | n | bytes a/b (delta) | Where the drift is |
|---|---|---|---|---|---|
| **main/zlb.c** | **53.53** | 0x930 | 1 | 4/4 (+0) | one word at `zlbDecompress+0x14` — the demo is a byte-level oracle for the whole TU; the 53% is pure source-spelling divergence |
| dlls/engine/6/6.c | 99.97 | 0x2414 | 1 | 0x10/0xC (-4) | `sky2_run+0xA4` |
| main/pi_pathsearch.c | 99.92 | 0xC34 | 1 | 0x18/0x18 (+0) | `pathSearchExpandNode+0xE8` |
| dlls/engine/60/60.c | 99.88 | 0x141C | 2 | 0xC/0x14 (+8) | `Link_render+0x188`, `Link_setup+0x260` |
| main/objanim.c | 99.90 | 0x1B34 | 2 | 0xA8/0xB0 (+8) | `ObjAnim_SetBlendMove`, `Object_ObjAnimSetPrimaryBlendMove` |
| dlls/engine/78/78.c | 99.93 | 0xDDC | 2 | 0x9C/0x64 (-0x38) | `CameraModeWorldMap_free/_update` tail |
| dlls/objects/241_InvHit/InvHit.c | 99.90 | 0x68C | 2 | 0x68/0x1A0 (+0x138) | `InvHit_update` — demo has extra code here |
| main/vecmath.c | 99.81 | 0x13CC | 2 | 0x140/0x18 (-0x128) | `interpolate` tweak; `RandomTimer_UpdateRangeTrigger` absent from demo |
| main/trig.c | 99.98 | 0xA30 | 2 | 0x340/0 (-0x340) | `fsin16HighPrecision`/`fcos16HighPrecision` retail-only; rest identical |
| main/acosf.c | 99.41 | 0x860 | 2 | 0x35C/0 (-0x35C) | `atanf`/`atan2fHighPrecision` retail-only; `atan2f` core identical |
| dlls/objects/455_DIMLavaSmas/DIMLavaSmas.c | 99.70 | 0x424 | 1 | 0x148/0x120 (-0x28) | [X-TU] region from `DIMCannon_init+0x22C` |
| main/gameloop_buttonobj.c | 98.22 | 0xEC | 1 | 0x14C/0x1C (-0x130) | [X-TU] region from `askProgressiveScanMode+0x324` |
| dlls/objects/691/691.c | 99.87 | 0xBD8 | 1 | 0xC38/0x5C (-0xBDC) | [X-TU] most of TU absent from demo; weak evidence |

## Table C — anti-worklist: heavily churned AND <100% (drift caveat mandatory)

Top rows by churn (n = overlapping regions, a+b = bytes touched):
player.c (99.80, 512 regions, 0x1EF90), tricky.c (99.97, 238, 0xCE00), engine/0 (99.79, 227,
0xCB38), 597 SnowBike (99.91, 44, 0xC930), pi_dolphin.c (99.92, 62, 0xA264), engine/5 (99.87,
31, 0x7828), expgfx.c (99.80, 95, 0x636C), track_dolphin.c (99.71, 56, 0x57E8), engine/7
(99.99, 57, 0x4D88), newshadows.c (98.81, 44, 0x4D10), engine/11 (99.74, 46, 0x4320),
objhits.c (99.73, 45, 0x3628), engine/2 (99.65, 88, 0x3468), shader.c (99.53, 65, 0x2D84),
229.c (99.76, 4, 0x2BC4), engine/21 (99.98, 20, 0x27C4), objprint_dolphin.c (99.88, 53,
0x2670), mm.c (99.83, 13, 0x2310), engine/23 (99.74, 28, 0x21DC), **model.c (92.27, 23,
0x1DA4 — biggest single match prize among sub-100 TUs, but the demo evidence carries real
drift)**, textrender_run.c (99.57, 28, 0x1C98), engine/66 (99.96, 43, 0x1770), camcontrol.c
(99.98, 40, 0x176C), WORLDplanet.c (99.48, 20, 0x16C0), object.c (99.97, 49, 0x1624),
BossDrakor.c (99.90, 20, 0x1584), tex_dolphin.c (99.79, 27, 0x14FC), 332.c (99.91, 14,
0x1384), dll_80136a40.c (99.79, 6, 0x1328), 294.c (99.97, 25, 0x1104), DR_LaserCan.c (99.48,
23, 0x1034), sharpclaw.c (99.89, 24, 0xC2C), 262.c (99.95, 24, 0xC24), MMP_moonroc.c (99.97,
21, 0xB28), Hcurves.c (99.83, 24, 0xA34), engine/53 (99.97, 20, 0x9E0), lightmap.c (99.70,
26, 0x814).

Middle band (3-19 regions, light caveat) completing the 85: Hcurves_romcurve.c (99.9957, only
0x38 bytes churn — nearly Table B), engine/22, engine/69, textrender.c, engine/28, engine/19,
578_DBstealerwo, 704.c, pi_videoinit.c, 429_SHthorntail, engine/24, pad.c, lightmap_draw.c,
engine/9, objprint.c, gametext_tail.c, 226.c, shadow_dolphin.c, modgfx/90, voxmaps.c,
engine/71, render.c, 488_SB_Galleon, modgfx/152, texture.c, subtitle.c, engine/68.

## Method notes / hazards for reruns

1. `report.json` unit key = `"main/" + path minus extension`; the summary TU label ==
   `splits.txt` unit == configure Object name. Against a stale report, map by `.text`
   `virtual_address`, never by name.
2. splits.txt parse hazard: 5 unit lines carry trailing options (`targsupp.s: comment:0`, the
   Runtime `__start.c`/`__mem.c`/`mem_TRK.c`, `__exception.s`). A parser keying on "ends with
   `:`" silently attributes their .text to the previous TU (this is why README §6b reads
   943/395; true figures 944/396).
3. Start-unit attribution overstates "stream-identical" by 37 TUs (regions spanning boundaries
   are labeled by starting TU). None of those 37 may be treated as drift-free; all were 100%
   matched anyway except three [X-TU] Table B rows and 429_SHthorntail.
4. Four TUs are configure-NonMatching yet 100% on .text fuzzy: 701.c, gametext.c,
   rcp_dolphin.c, track/intersect_render.c — data-side or link-order issues, not code frontier.

## Suggested attack order

zlb.c first (53% with a 4-byte-drift oracle), then Table A by size-weighted deficit:
textrender_boxtex.c, engine/3/3.c, the MSL trio (sincosf.c, math_8029454c.c,
exponentialsf.c), synth_seq_dispatch.c, synth_queue.c, 625.c.
