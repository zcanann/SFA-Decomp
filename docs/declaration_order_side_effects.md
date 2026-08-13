# Declaration order and side effects: the call-carrying blocks, adjudicated

`brute_match.side_effect_reorders` FLAGS a declaration permutation that changes the
relative order of a pair in which at least one initialiser calls something. Flagging is
not refusing: the sweep still measures the ordering, it only loses the right to APPLY it
unread. This file is the read.

## Why a flag is not a verdict

The flag is deliberately coarse -- it fires on a pure helper and on a macro that expands
to an array subscript. Three questions turn it into a verdict:

1. **Can the pair even move?** If one item's initialiser uses a name the other declares,
   the compiler refuses the reordering. Transitively: `a; b = f(a); c = b*b;` has no legal
   permutation at all.
2. **Does the partner evaluate anything?** A declaration with no initialiser generates no
   code, so moving it past a call changes nothing.
3. **Do the two evaluations interact?** A call is order-relevant when it has side effects
   (RNG, allocation, I/O, global mutation) *and* the partner reads or writes the same
   state -- or when its implementation cannot be read at all.

Only pairs that survive all three are hazards.

## The census

At the sub-100 population there are **48 call-carrying declaration blocks** out of 506 total.
**31 are inert by construction** -- no pair that touches an evaluated call is reorderable.
The other **17 carry at least one free pair**, adjudicated below.

| # | unit | function | blk | pairs | verdict |
| --- | --- | --- | --- | --- | --- |
| 1 | `dlls/engine/0/0.c` | `drawArwingHud` | 0 | 1&#8596;6 | **INDEPENDENT** |
| 2 | `dlls/engine/0/0.c` | `drawViewFinderHud` | 9 | 0&#8596;1 0&#8596;2 1&#8596;2 | **IMPURE-BUT-DISJOINT** |
| 3 | `dlls/engine/0/0.c` | `pauseMenuDrawStatusPage` | 1 | 0&#8596;1 | **ORDER-RELEVANT** |
| 4 | `dlls/objects/195_Player/player.c` | `playerState25` | 1 | 0&#8596;1 | **INDEPENDENT** |
| 5 | `dlls/objects/195_Player/player.c` | `playerStateAttack` | 1 | 0&#8596;1 | **INDEPENDENT** |
| 6 | `dlls/objects/195_Player/player.c` | `playerUpdate` | 0 | 0&#8596;1 1&#8596;4 | **INDEPENDENT** |
| 7 | `dlls/objects/226/226.c` | `staff_update` | 0 | 0&#8596;3 | **INDEPENDENT** |
| 8 | `main/acosf.c` | `atan2f` | 0 | 0&#8596;1 | **INDEPENDENT** |
| 9 | `main/acosf.c` | `atan2fHighPrecision` | 0 | 0&#8596;1 | **INDEPENDENT** |
| 10 | `main/acosf.c` | `atan2f_fast` | 0 | 0&#8596;1 | **INDEPENDENT** |
| 11 | `main/newshadows.c` | `allocLotsOfTextures` | 0 | 5&#8596;14 6&#8596;14 7&#8596;14 | **IMPURE-BUT-DISJOINT** |
| 12 | `main/objprint_dolphin.c` | `modelDoRenderInstrs` | 1 | 0&#8596;1 | **UNRESOLVABLE** |
| 13 | `main/objprint_dolphin.c` | `modelDoRenderInstrs` | 2 | 0&#8596;1 | **INDEPENDENT** |
| 14 | `main/objprint_dolphin.c` | `objSetupRenderOpGxState` | 2 | 0&#8596;1 | **INDEPENDENT** |
| 15 | `main/pi_dolphin.c` | `mapLoadDataFile` | 1 | 0&#8596;1 | **INDEPENDENT** |
| 16 | `main/render.c` | `modelRenderInterpolateRootTransform` | 1 | 0&#8596;2 | **INDEPENDENT** |
| 17 | `main/shader.c` | `doPendingMapLoads` | 4 | 0&#8596;1 | **INDEPENDENT** |

### The verdicts in full

**1. `dlls/engine/0/0.c` :: `drawArwingHud` block 0 — INDEPENDENT**

```c
/*0*/ u8 bombSlot;
/*1*/ GameObject* arwing = getArwing();   // CALL: getArwing
/*2*/ int health;
/*3*/ int maxHealth;
/*4*/ int fullPips;
/*5*/ int bombs;
/*6*/ ArwingScoreText score = sArwingBlankScore;
/*7*/ int req;
/*8*/ int rings;
/*9*/ u32 i;
/*10*/ int partialFrame;
/*11*/ int maxPips;
/*12*/ u32 pip;
/*13*/ u8 texIdx;
```

`getArwing` returns `gArwing`. The partner copies the global `sArwingBlankScore`.

**2. `dlls/engine/0/0.c` :: `drawViewFinderHud` block 9 — IMPURE-BUT-DISJOINT**

```c
/*0*/ f32 farP = Camera_GetFarPlane();   // CALL: Camera_GetFarPlane
/*1*/ f32 nearP = Camera_GetNearPlane();   // CALL: Camera_GetNearPlane
/*2*/ int depth = depthReadRequestPoll(0x140, 0xf0, drawViewFinderHud);   // CALL: depthReadRequestPoll
/*3*/ f32 dist = (-farP * nearP) / (((f32)(u32)depth / 16777215.0f - 1.0f) * (farP - nearP) - nearP);
```

`depthReadRequestPoll` APPENDS to `gDepthReadPendingQueue`/`gDepthReadPendingCount` (src/track/intersect*.c). The partners read `gCameraFarPlane`/`gCameraNearPlane` (src/main/camera.c). Disjoint state, so the three pairs are behaviour-preserving today -- but the flag must stay: add a camera-writing item and it stops being.

**3. `dlls/engine/0/0.c` :: `pauseMenuDrawStatusPage` block 1 — ORDER-RELEVANT**

```c
/*0*/ s32 rnd1 = randomGetRange(0, 0x1e) * 2;   // CALL: randomGetRange
/*1*/ s32 rnd2 = randomGetRange(0, 0x1e) * 2;   // CALL: randomGetRange
```

`randomGetRange` calls `rand()`. The two draws are consumed as DIFFERENT arguments of `pauseMenuDrawTextureRegion(..., rnd2, rnd1)`, so swapping the declarations swaps which draw reaches which parameter. Never auto-apply.

**4. `dlls/objects/195_Player/player.c` :: `playerState25` block 1 — INDEPENDENT**

```c
/*0*/ f32 deltaX = interpolate(targetVelX - inner->smoothVelX, 0.25f, timeDelta);   // CALL: interpolate
/*1*/ f32 deltaZ = interpolate(targetVelZ - inner->smoothVelZ, 0.25f, timeDelta);   // CALL: interpolate
```

`interpolate` is arithmetic over `powfBitEstimate`, itself pure bit-manipulation of its arguments.

**5. `dlls/objects/195_Player/player.c` :: `playerStateAttack` block 1 — INDEPENDENT**

```c
/*0*/ f32 v = (f32)(u8)enemy_getFreezeRecoverSeconds((GameObject*)((PlayerState*)state)->baddie.targetObj);   // CALL: enemy_getFreezeRecoverSeconds
/*1*/ int slot2 = inner->moveSlots + (u32)inner->moveSlotIndex * 0xb0;
```

`enemy_getFreezeRecoverSeconds` reads `obj->extra` and `state->freezeRecoverTimer` and writes nothing.

**6. `dlls/objects/195_Player/player.c` :: `playerUpdate` block 0 — INDEPENDENT**

```c
/*0*/ int inner = (int)obj->extra;
/*1*/ int cam = (int)Camera_GetCurrent();   // CALL: Camera_GetCurrent
/*2*/ f32 zero;
/*3*/ f32 six;
/*4*/ f32 t = ((PlayerState*)inner)->cutsceneTimer;
```

`Camera_GetCurrent` returns `&gCameras[gCameraCurrentViewIndex]`. Neither partner touches camera state.

**7. `dlls/objects/226/226.c` :: `staff_update` block 0 — INDEPENDENT**

```c
/*0*/ u8* state = obj->extra;
/*1*/ StaffSwipeSlot* swp;
/*2*/ int n;
/*3*/ ObjModel* model = Obj_GetActiveModel(obj);   // CALL: Obj_GetActiveModel
```

`Obj_GetActiveModel` returns `obj->anim.banks[obj->anim.bankIndex]`. The partner reads `obj->extra`.

**8. `main/acosf.c` :: `atan2f` block 0 — INDEPENDENT**

```c
/*0*/ float absoluteX = __fabsf(x);   // CALL: __fabsf
/*1*/ float absoluteY = __fabsf(y);   // CALL: __fabsf
/*2*/ float axisRatio;
/*3*/ float ratioSquared;
/*4*/ float firstQuadrantAngle;
/*5*/ int quadrantSigns;
```

`__fabsf` is a compiler intrinsic over its argument.

**9. `main/acosf.c` :: `atan2fHighPrecision` block 0 — INDEPENDENT**

```c
/*0*/ float absoluteX = __fabsf(x);   // CALL: __fabsf
/*1*/ float absoluteY = __fabsf(y);   // CALL: __fabsf
/*2*/ double axisRatio;
/*3*/ double ratioSquared;
/*4*/ double firstQuadrantAngle;
/*5*/ int quadrantSigns;
```

`__fabsf` is a compiler intrinsic over its argument.

**10. `main/acosf.c` :: `atan2f_fast` block 0 — INDEPENDENT**

```c
/*0*/ float absoluteX = __fabsf(x);   // CALL: __fabsf
/*1*/ float absoluteY = __fabsf(y);   // CALL: __fabsf
/*2*/ float axisRatio;
/*3*/ float ratioSquared;
/*4*/ float firstQuadrantAngle;
/*5*/ s32 quadrantSigns;
```

`__fabsf` is a compiler intrinsic over its argument.

**11. `main/newshadows.c` :: `allocLotsOfTextures` block 0 — IMPURE-BUT-DISJOINT**

```c
/*0*/ int i;
/*1*/ int j;
/*2*/ f32 rc2;
/*3*/ Texture* frameTexture;
/*4*/ f32 rc;
/*5*/ NewShadowData* shadowData = (NewShadowData*)gNewShadowEntries;
/*6*/ Texture** renderTargets = shadowData->castTextures;
/*7*/ Texture** frameTextures = shadowData->frameTextures;
/*8*/ f32 cy;
/*9*/ int off;
/*10*/ f32 cx;
/*11*/ f32 d2;
/*12*/ f32 v;
/*13*/ int bumpRowOff;
/*14*/ u8 saved = mmSetDelay(1);   // CALL: mmSetDelay
```

`mmSetDelay` writes `gMmUseHeap3` and `gMmOpCount` (src/main/mm.c). The partners cast/read `gNewShadowEntries`. Disjoint. Hoisting it across an ALLOCATION would matter; there is none in this block.

**12. `main/objprint_dolphin.c` :: `modelDoRenderInstrs` block 1 — UNRESOLVABLE**

```c
/*0*/ GameObject* player = Obj_GetPlayerObject();   // CALL: Obj_GetPlayerObject
/*1*/ int* cam = (int*)(*gCameraInterface)->getCamera();   // CALL: getCamera
```

`Obj_GetPlayerObject` is pure, but the partner is `(*gCameraInterface)->getCamera()` -- a DLL vtable slot whose implementation is not in this tree. Purity cannot be established, so treat as order-relevant.

**13. `main/objprint_dolphin.c` :: `modelDoRenderInstrs` block 2 — INDEPENDENT**

```c
/*0*/ f32 d = 2e+01f + (((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale + *(f32*)&((GameObject*)obj)->anim.targetObj);
/*1*/ f32 dist = Camera_DistanceToCurrentViewPosition(player->anim.worldPosX, player->anim.worldPosY, player->anim.worldPosZ);   // CALL: Camera_DistanceToCurrentViewPosition
```

`Camera_DistanceToCurrentViewPosition` reads `gCameras[gCameraCurrentViewIndex]` and returns `sqrtf(...)`. The partner reads `obj->anim` fields.

**14. `main/objprint_dolphin.c` :: `objSetupRenderOpGxState` block 2 — INDEPENDENT**

```c
/*0*/ void* t = textureIdxToPtr(((Shader*)op)->auxTextureIndex);   // CALL: textureIdxToPtr
/*1*/ int nl = gObjSelectedLightCount + 1;
```

`textureIdxToPtr` reads `gLoadedTextureCount`/`gLoadedTextures` only. The partner reads `gObjSelectedLightCount`.

**15. `main/pi_dolphin.c` :: `mapLoadDataFile` block 1 — INDEPENDENT**

```c
/*0*/ int nOwned = 0;
/*1*/ s16 o25 = MLDF_OWNER(0x25);   // CALL: MLDF_OWNER
/*2*/ s16 o47;
```

`MLDF_OWNER(s)` is `#define MLDF_OWNER(s) (tbl->owners[s])` -- an array read, not a call. The detector flags a macro invocation by shape, the documented conservative direction. The partner is the constant `0`.

**16. `main/render.c` :: `modelRenderInterpolateRootTransform` block 1 — INDEPENDENT**

```c
/*0*/ s64 h = render_readPackedU16(tp);   // CALL: render_readPackedU16
/*1*/ u64 nib = h & 0xf;
/*2*/ u64 sample = 0;
/*3*/ u32 hw = h;
```

`render_readPackedU16` is `static inline` and returns `*(u16*)address`. The partner is the constant `0`.

**17. `main/shader.c` :: `doPendingMapLoads` block 4 — INDEPENDENT**

```c
/*0*/ int mapId = gShaderCurMapEventId;
/*1*/ int sz = (int)((u32)getDataFileSize(MLDF_FILEID_MAPINFO_BIN) >> 5);   // CALL: getDataFileSize
```

`getDataFileSize` only reads `gResourceFileBuffers`/`gResourceFileSizes` (its failure path is a deliberate null-store assert). The partner reads `gShaderCurMapEventId`.

### Inert by construction

Every pair that would move an evaluated call is either chained through a name the
compiler enforces, or paired only with declarations that evaluate nothing.

| unit | function | blk | items | call |
| --- | --- | --- | --- | --- |
| `dlls/engine/0/0.c` | `pauseMenuDraw` | 1 | 2 | `getCurCharacterState` |
| `dlls/engine/78/78.c` | `CameraModeWorldMap_update` | 2 | 5 | `ObjList_FindObjectById` |
| `dlls/objects/195_Player/player.c` | `playerBuildLedgeClimbProbe` | 1 | 3 | `sqrtf` |
| `dlls/objects/195_Player/player.c` | `playerBuildWallTransitionProbe` | 2 | 3 | `sqrtf` |
| `dlls/objects/195_Player/player.c` | `playerRender` | 2 | 2 | `Obj_GetActiveModel` |
| `dlls/objects/195_Player/player.c` | `playerState1B` | 2 | 2 | `getById` |
| `dlls/objects/195_Player/player.c` | `playerStateClimbOntoLadder` | 3 | 3 | `Player_GetActiveModel` |
| `dlls/objects/195_Player/player.c` | `player_SeqFn` | 5 | 3 | `objGetAllOfType` |
| `dlls/objects/229/229.c` | `Shield_update` | 2 | 2 | `fsin16` |
| `dlls/objects/241_InvHit/InvHit.c` | `InvHit_update` | 1 | 4 | `sqrtf` |
| `dlls/objects/241_InvHit/InvHit.c` | `InvHit_update` | 2 | 2 | `Obj_GetPlayerObject, Player_GetTargetObject` |
| `dlls/objects/466_WORLDplanet/WORLDplanet.c` | `worldplanet_update` | 2 | 2 | `ObjList_FindObjectById` |
| `dlls/objects/704/704.c` | `titleScreenDrawMenuFrame` | 1 | 5 | `f32` |
| `dolphin/MSL_C/PPCEABI/bare/H/math_8029454c.c` | `mathTanf` | 0 | 4 | `trigReduceQuadrant` |
| `main/objprint.c` | `staffUpdateSegmentTransforms` | 2 | 3 | `OBJPRINT_ACTIVE_BANK_INDEX, OBJPRINT_ATTACH_POINTS` |
| `main/objprint_dolphin.c` | `objRenderModel` | 0 | 12 | `Obj_GetActiveModel` |
| `main/objprint_dolphin.c` | `objSetupRenderOpGxState` | 3 | 3 | `OBJPRINT_MODEL_DEF` |
| `main/sincosf.c` | `mathSinCosf` | 0 | 5 | `trigReduceQuadrant` |
| `main/tex_dolphin.c` | `collectShadowTrackTriangles` | 0 | 8 | `trackGetBlockDescriptors` |
| `main/texture.c` | `textureInitGXTexObj` | 1 | 3 | `GXGetTexObjFmt` |
| `main/track_dolphin.c` | `trackBuildBlockTriangles` | 1 | 2 | `mapBlockGetPolygon` |
| `main/track_dolphin.c` | `trackResolveSurfacePenetration` | 3 | 3 | `atan2fHighPrecision, mathCosfHighPrecision, sqrtf` |
| `main/track_dolphin.c` | `trackResolveSurfacePenetration` | 5 | 3 | `atan2fHighPrecision, mathSinfHighPrecision, sqrtf` |
| `main/trig.c` | `fcos16` | 0 | 3 | `fastCastS16ToFloat` |
| `main/trig.c` | `fcos16Approx` | 0 | 3 | `fastCastS16ToFloat` |
| `main/trig.c` | `fcos16HighPrecision` | 0 | 4 | `fastCastS16ToFloat` |
| `main/trig.c` | `fcos16Precise` | 0 | 3 | `fastCastS16ToFloat` |
| `main/trig.c` | `fsin16` | 0 | 3 | `fastCastS16ToFloat` |
| `main/trig.c` | `fsin16Approx` | 0 | 3 | `fastCastS16ToFloat` |
| `main/trig.c` | `fsin16HighPrecision` | 0 | 4 | `fastCastS16ToFloat` |
| `main/trig.c` | `fsin16Precise` | 0 | 3 | `fastCastS16ToFloat` |

The `trig.c` family (8 rows) and `mathTanf` are the extreme case: every declaration
initialises from the one above it, so the block has no legal permutation whatsoever and
a sweep of it is exhaustive at size one.

## Exposure of landed work

Re-read, hunk by hunk, at `51ddac2e01`. Of the five landed ordering commits, only two
touch a file that holds a call-carrying block:

- `eb8b31b6b6` `player.c` swaps `int i;` and `int* list;` in `playerState08` -- two BARE
  declarations, no initialiser, nothing evaluated, and a different function from any row
  above.
- `db1d0f75fe` `objprint_dolphin.c` hoists `f32 sc2;` to function scope in
  `modelDoRenderInstrs` and leaves the initialisation in place as an assignment. The
  moved item is a bare declaration; no evaluation moves. It is block 0, not the flagged
  block 1.

Zero exposure. This is prevention, not repair.

## Controls

`python3 tools/vacuity_audit.py --family parser` carries the subjects and the ablations:
the PRNG pair must be flagged and the identity ordering must not; a plain declaration, a
cast and a field read must stay quiet; the five indirect-dispatch spellings must be seen
and the pre-fix lookbehind must miss all five; blinding the call scanner must make the
flag vanish; and the gate must be WIRED into both sweepers, not merely defined.
