# Curves

> Source: [Rena Kunisaki's SFA wiki](https://github.com/RenaKunisaki/StarFoxAdventures/wiki/Curves). Reverse-engineering notes; not independently verified here.

Curves are objects that define a path for other objects to follow. Not to be confused with
*AnimCurv* (documented on the wiki's Scripting page), which defines curves for animation
sequences; this page is about the "RomCurve" network used by objects that move during play
(e.g. barrel grabbers).

## RomCurve

Object ID 0x491, named `"curve"` but often referred to as "romcurve", handled by DLL 0x125.

These always seem to appear at the end of the romlist and reuse the placement header's
`acts0`, `loadFlags`, `acts1`, `bound`, and `cullDist` fields differently (unresearched).

Despite the name, each `RomCurve` object defines only one **point**; a curve is made from
several linked points (and isn't really curved — see "Curves in memory" below for the
in-memory interpolation).

Objdef parameters:

| Offs | Type      | Description |
|------|-----------|--------------|
| 0x18 | u8        | Action |
| 0x19 | u8        | Type |
| 0x1A | ?         | ? |
| 0x1B | u8        | Flags |
| 0x1C | ObjectId  | next1 |
| 0x20 | ObjectId  | next2 |
| 0x24 | ObjectId  | next3 |
| 0x28 | ObjectId  | next4 |
| 0x2C | s8        | rotZ |
| 0x2D | s8        | rotY |
| 0x2E | s8        | rotX |
| 0x2F | ?         | Probably padding |
| 0x30 | GameBit16 | Enable |
| 0x32 | GameBit16 | Disable |

* **Action**: tells the object what to do when it reaches this point. Meaning depends on the object.
* **Type**: used to find the correct curve; has no effect on the curve itself, but objects look
  for a nearby curve of a specific type.
* **Flags**: disables individual "next" links (reason unknown):
  * 0x01: disable next1
  * 0x02: disable next2
  * 0x04: disable next3
  * 0x08: disable next4
* **nextN**: the Object Unique ID of the next curve point to move toward from this one — up to
  4 outgoing links per point, unused entries set to -1 (branching paths).
* **rot**: rotation, which can influence how some objects follow the path.
* **Enable**: if not -1, a GameBit which must be nonzero for the curve to be returned by certain
  "find nearby curve" functions.
* **Disable**: as above, but the GameBit must be zero.

### Next-point selection algorithm

An object choosing its next point:

1. Collect every valid "next" point into a list. A point is valid if:
   * it is not the point the object came from (prevents bouncing between two points),
   * it does not specify Object Unique ID -1, and
   * its disable flag is not set.
2. If the path index is -1, return a random point from the list.
3. Otherwise, if the path index is >= the list's length, return the last entry.
4. Otherwise, return the specified entry.

Multiple paths can share segments this way without redundant data — usually "next2" is the
"forward" path and "next1" the "reverse" path, but this is only convention, not enforced. A
curve with no "next" point (all -1) can define a single target point for an object. Objects can
get confused following curves (going backward, stopping, or getting lost) if a curve isn't
perfect — observed even in an unmodified game.

### Known types

| Type | Used by |
|------|---------|
| 0x01 | Everything in Dragon Rock Bottom |
| 0x02 | WB (flying enemy) |
| 0x03 | HagabonMK2 |
| 0x15 | DIM2PathGenerator |
| 0x16 | Something important — the DLL has a method that looks specifically for this type |
| 0x19 | Barrel grabbers in DarkIce Mines |
| 0x1F | Tunnels you can crawl through (path followed exactly, even through the air; action ignored while crawling) |
| 0x23 | CurveFish |
| 0x24 | Used by Tricky |
| 0x2A | DrakorHoverPad |

It's not clear whether all listed types are the complete set.

## Curves in memory

DLL 0x14 (maybe "network curve") is responsible for interpolating the RomCurve point data into
in-between positions; not extensively researched by the wiki author.

There are at least three curve-interpolation kinds (unrelated to the RomCurve *Type* field
above, which is for finding a curve, not evaluating it): Hermite and Bezier require a multiple
of four points and appear to need points defined in order (point, control 1, control 2); the
others don't use control points at all. It's unclear whether all three are actually used.

## In this codebase

Cross-references verified by reading the source at the paths below.

### The RomCurve object (DLL 0x125) and its objdef

- `src/main/dll/dll_0125_curve.c` — DLL 0x125's `"curve"` object. Header comment records its TU
  range (`0x80171300`-`0x801713D8`); `config/GSAE01/symbols.txt` confirms `curve_func0B` at
  `0x80171300` through `curve_render` at `0x80171320`, and `gCurveObjDescriptor` at
  `0x80320AC0`. `curve_init` reads the placement's rotation bytes into `obj->rotX/rotY/rotZ`
  and picks a root-motion scale — this is the "rot: defines rotation" behaviour the wiki notes.
- Objdef layout for a single RomCurve point, matched **exactly** offset-for-offset against the
  wiki's table, is `RomCurvePlacementDef` in `include/main/dll/dll_0015_curves.h`:
  - `RomCurveDef` (the `base` member) covers 0x18-0x2B: `action` (0x18), `type` (0x19), `pad1A`
    (0x1A), `blockedLinkMask` (0x1B, = wiki's "Flags"), `linkIds[4]` (0x1C/0x20/0x24/0x28, =
    next1..next4) — all `STATIC_ASSERT`-verified.
  - `RomCurvePlacementDef` adds `rotZ`/`rotY`/`rotX`/`pad2F` at exactly 0x2C/0x2D/0x2E/0x2F,
    matching the wiki's rotZ/rotY/rotX/padding row-for-row (`STATIC_ASSERT`-verified in the
    same header).
  - Enable/Disable GameBit16 fields (wiki 0x30/0x32) correspond to `requiredBit`/`forbiddenBit`
    (`s16`, offsets 0x30/0x32) in the AI-pathing overlay `ObjfsaRomCurveDef`
    (`include/main/dll/objfsa_romcurve.h`) — see below for why there are two overlay structs.
  - A second, lighter overlay of the same 0x18+ layout, `ObjfsaRomCurveDef`
    (`include/main/dll/objfsa_romcurve.h`), is used by the pathing/AI DLL (0x14) instead of
    `RomCurvePlacementDef`; it collapses the rotZ/rotY/rotX triplet into a single `s8 angle` +
    `u8 pad2D[3]`, which is imprecise — see "Ready-to-adopt code" below.
- `RomCurveDef`/`RomCurvePoint`/`CurvesCollisionState` and all the `ROMCURVE_*` layout
  `#define`s live in `include/main/dll/dll_0015_curves.h`.

### Next-point selection algorithm

- `RomCurve_goNextPoint` and `RomCurve_func29` (`src/main/dll/dll_0014_unk.c`) implement the
  wiki's next-point algorithm: they walk `linkIds[4]`, test `blockedLinkMask` bit-by-bit (the
  wiki's Flags 0x01/0x02/0x04/0x08 "disable nextN" bits), skip `-1` entries, and call
  `randomGetRange` for the "pick random from the valid list" case.
- `RomCurve_getControlPointId` / `RomCurve_getUnblockedControlPointId`
  (`src/main/dll/dll_0014_unk.c`) take an explicit `exclude` id parameter — the "not the point
  the object came from" bounce-prevention rule from the wiki.
- Enable/Disable GameBit gating is implemented in `Objfsa_FindNearestEnabledCurveType24`
  (`src/main/dll/dll_0014_unk.c`): it reads `requiredBit`/`forbiddenBit` at +0x30/+0x32 and
  checks `gbId == -1 || mainGetBit(gbId) != 0` (Enable) and the mirrored zero-check
  (Disable) — matching the wiki's "if not -1" semantics exactly.

### Known types, verified against this codebase

| Type | Wiki says | Found here |
|------|-----------|------------|
| 0x03 | HagabonMK2 | Confirmed exactly: `hagabonMK2_update`/`hagabonMK2_updateB` (`src/main/dll/firecrawler.c`, dispatched from the enemy mega-DLL `dll_00C9_enemy.c`) implement HagabonMK2 (`anim.seqId 0x7c8`, per that file's header comment table cross-referenced against retail `OBJECTS.bin` names). It follows ROM curve paths via `RomCurveWalker`/`gRomCurveInterface`/`Curve_AdvanceAlongPath`, same as the rest of the `crawler_*` family in that TU. (A separate, unrelated plain "Hagabon" enemy also exists as DLL 0xDF/0xE0 — `src/main/dll/dll_00DF_hagabon.c` / `dll_00E0_swarmbaddie.c` — worth not confusing the two; `trickyfollow.c`'s header comment explicitly calls DLL 0xDF "unrelated".) |
| 0x15 | DIM2PathGenerator | `ROMCURVE_TYPE_ACTION` (`= 0x15`, `include/main/dll/dll_0015_curves.h`) is checked in `curves_findByAction` (`src/main/dll/dll_0014_unk.c`). Numerically the same value is separately named `ROMCURVE_TYPE_SCALE_OVERRIDE_15` for an unrelated per-object root-motion-scale branch in `curve_init` (`dll_0125_curve.c`) — two different DLLs independently overloading the same Type id. |
| 0x16 | "Something important... the DLL has a method that looks specifically for this type" | Confirmed exactly: `curves_findNearestOfType16` (`src/main/dll/dll_0014_unk.c`) hardcodes `curve->type == 0x16`. |
| 0x23 | CurveFish | Confirmed exactly: `gCurveFishCurveQueryKey = 0x23` in `src/main/dll/dll_0103_curvefish.c` (DLL 0x103, `curvefish` object). |
| 0x24 | Used by Tricky | Confirmed exactly: `Objfsa_FindNearestCurveType24` / `Objfsa_FindNearestEnabledCurveType24` (`src/main/dll/dll_0014_unk.c`) hardcode `type == 0x24`; called from `src/main/dll/tricky_substates.c`, `src/main/dll/tricky_flameguard.c`, and `src/main/dll/dll_00C4_tricky.c`. |
| 0x2A | DrakorHoverPad | `src/main/dll/dll_0271_drakorhoverpad.c` (DLL 0x271) follows a "ROM spline/curve network"; its local `DrakorCurveNode` overlay reuses the placement's rotZ/rotY/rotX bytes (0x2C/0x2D/0x2E) as `tangentYaw`/`tangentPitch`/`tangentMag` to derive bob/banking velocity — direct confirmation of the wiki's "rot: ... can influence how some objects follow the path." No literal `== 0x2A` type check found (likely passed in via a caller-side type filter, not visible in this TU). |
| 0x01, 0x02, 0x19, 0x1F | Dragon Rock Bottom / WB / DIM barrel grabbers / crawl tunnels | Not found. These types are presumably passed as filter arguments from each object's own DLL when it calls the curve-find interface, rather than hardcoded in the shared curve DLL; the specific DLLs for "WB" and Dragon Rock Bottom's objects were not identified by name in this pass. |
| 0x17 | *(not on the wiki)* | `RomCurve_func16` (`src/main/dll/dll_0014_unk.c`) hardcodes `type == 0x17` — a special-cased type the wiki's "Known types" list doesn't mention. Worth flagging upstream. |

### DLL 0x14 "network curve" and interpolation

- `src/main/dll/dll_0014_unk.c` is DLL 0x14. Its header comment names it "RomCurve navigation
  library + ObjFSA walk-group spatial query" — this is the wiki's "DLL 0x14 (maybe 'network
  curve')". `RomCurveWalker.moveNetwork` (`include/main/dll/curve_walker.h`, offset 0x90) is
  named directly after this.
- The actual point-to-point interpolation math the wiki says is "not extensively researched"
  lives in `src/main/curves.c` (generic `Curve` evaluator, `include/main/curve.h`):
  `curvesSetupMoveNetworkCurve` / `curvesMove` build a segment-length table and set up
  `curve->eval`/`curve->coeffFn`; `Curve_AdvanceAlongPath` steps a `Curve` along its path by a
  time delta.
- The three interpolation kinds the wiki mentions map onto the four evaluator functions in
  `src/main/curves.c` / `include/main/curve.h`:
  - Hermite: `Curve_EvalHermite` / `Curve_BuildHermiteCoeffs`
  - Bezier: `Curve_EvalBezier` (no separate coeff-builder — computed inline)
  - "others" (no control points): `Curve_EvalLinear`, `Curve_EvalCatmullRom`, and
    `Curve_EvalBSpline` / `Curve_BuildBSplineCoeffs`. Concretely, `curvesMove` /
    `curvesSetupMoveNetworkCurve` only enforce the "multiple of four points" rule when
    `curve->eval == Curve_EvalBezier || curve->eval == Curve_EvalHermite` — exactly the
    two-kinds-vs-the-rest split the wiki describes.
- `RomCurveWalker` (`include/main/dll/curve_walker.h`) is the walker state the RomCurve_*
  family operates on (`phase`, `posX/Y/Z`, `tangentX/Y/Z`, `reverse`, per-axis hermite
  coefficient sets, and `node94..nodeA4` curve-node history/current/next pointers).
- `RomCurveSegmentProjection` (`include/main/dll/rom_curve_segment_projection.h`) and
  `RomCurveInterface` (`include/main/dll/rom_curve_interface.h`, the `gRomCurveInterface`
  vtable every consuming DLL goes through) round out the curve-following API surface.

### Not the same system (naming collisions worth flagging)

- `CurveHeapNode` / `CurveHeap_SiftDown` (`include/main/engine_shared.h`,
  `src/main/curves.c`/`src/main/voxmaps.c`) are an unrelated priority-queue heap used by the
  voxel-map pathfinder (A*-style open list) — nothing to do with RomCurve or spline curves;
  the shared name is a coincidence of both living in `curves.c`.
- `ObjAnim_SampleRootCurvePhase`, `objCurveInterpolate`, `RomCurveInterp_*`, and
  `ObjSeq_UpdateCurvePosition`/`ObjSeq_RebuildCurveStateToFrame`/`ObjSeq_ApplyFrameCurves`
  (`src/main/objseq.c`, per `config/GSAE01/symbols.txt`) look like this codebase's side of the
  wiki's separately-documented **AnimCurv** system (animation-sequence root-motion curves), not
  the RomCurve network this page covers — flagged here only to avoid confusing the two, per the
  wiki's own opening disambiguation.

## Ready-to-adopt code

Two write-ups the wiki backs with concrete values that this codebase doesn't yet centralize:

1. `ObjfsaRomCurveDef`'s tail (`include/main/dll/objfsa_romcurve.h`) currently reads:
   ```c
   s8 angle;
   u8 pad2D[3];
   ```
   at offsets 0x2C-0x2F. Both the wiki's objdef table and this codebase's own
   `RomCurvePlacementDef` (`dll_0015_curves.h`, offsets 0x2C/0x2D/0x2E/0x2F) and
   `DrakorCurveNode` (`dll_0271_drakorhoverpad.c`, same offsets named
   `tangentYaw`/`tangentPitch`/`tangentMag`) show this is really three separate one-byte fields,
   not one byte of "angle" plus 3 bytes of padding. A maintainer touching this header could
   tighten it to match the sibling structs:
   ```c
   s8 rotZ;   /* 0x2C, aka tangentYaw in DrakorCurveNode's per-node overlay */
   s8 rotY;   /* 0x2D, aka tangentPitch */
   u8 rotX;   /* 0x2E, aka tangentMag */
   u8 pad2F;
   ```

2. The wiki's "Known types" table has no equivalent named constant set in this codebase — every
   consumer above spells the type out as a bare hex literal (`0x16`, `0x17`, `0x23`, `0x24`,
   `0x15`, ...). A maintainer could centralize the *verified* subset (only the ones this pass
   confirmed against live code) alongside the existing `ROMCURVE_TYPE_*` constants in
   `dll_0015_curves.h`:
   ```c
   /* RomCurve objdef Type field (offset 0x19) - selects which curve network an
    * object's "find nearby curve" query targets. Only literal type checks
    * confirmed in matched/live code are named here; see docs/wiki/Curves.md
    * for the full "Known types" list including unverified entries. */
   #define ROMCURVE_TYPE_HAGABON_MK2   0x03 /* firecrawler.c hagabonMK2_update/B, DLL 0xC9 */
   #define ROMCURVE_TYPE_DIM2_PATHGEN  0x15 /* == ROMCURVE_TYPE_ACTION; curves_findByAction */
   #define ROMCURVE_TYPE_16            0x16 /* curves_findNearestOfType16 - purpose still unclear */
   #define ROMCURVE_TYPE_17            0x17 /* RomCurve_func16 - not documented upstream */
   #define ROMCURVE_TYPE_CURVEFISH     0x23 /* dll_0103_curvefish.c: gCurveFishCurveQueryKey */
   #define ROMCURVE_TYPE_TRICKY        0x24 /* Objfsa_FindNearest(Enabled)CurveType24 */
   ```
   (Left as `#define`s rather than an `enum` since `ROMCURVE_TYPE_ACTION`/`ROMCURVE_TYPE_SCALE_OVERRIDE_15`
   next to them in `dll_0015_curves.h` already use that convention.)
