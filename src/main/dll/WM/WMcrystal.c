#include "ghidra_import.h"
#include "main/mapEventTypes.h"
#include "main/dll/WM/WMcrystal.h"
#include "main/objanim_update.h"


#pragma peephole off
#pragma scheduling off
extern undefined4 FUN_800067c0();
extern undefined4 FUN_800067e8();
extern undefined4 FUN_80006824();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern int ObjHits_GetPriorityHitWithPosition();
extern undefined4 FUN_80039520();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800810f8();
extern undefined4 FUN_80081120();
extern undefined4 FUN_8011eb10();
extern undefined4 FUN_801dd5e4();
extern undefined4 FUN_80286830();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4 DAT_80328658;
extern undefined4 DAT_803286b0;
extern f64 DOUBLE_803e62a8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803e6288;
extern f32 FLOAT_803e628c;
extern f32 FLOAT_803e6290;
extern f32 FLOAT_803e6294;
extern f32 FLOAT_803e6298;
extern f32 FLOAT_803e629c;
extern f32 FLOAT_803e62a0;
extern f32 FLOAT_803e62b4;
extern f32 FLOAT_803e62b8;
extern f32 FLOAT_803e62bc;
extern f32 FLOAT_803e62c0;
extern f32 FLOAT_803e62c4;
extern f32 FLOAT_803e62c8;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 timeDelta;
extern f32 lbl_803E55F0;
extern f32 lbl_803E55F4;
extern f64 lbl_803E5610;
extern f32 lbl_803E5618;
extern f32 lbl_803E561C;
extern f32 lbl_803E5620;
extern f32 lbl_803E5624;
extern f32 lbl_803E5628;

extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_PlayFromObjectLimited(int obj, int sfxId, int maxCount);
extern void objLightFn_8009a1dc(int obj, f32 scale, void *params, int mode, int arg);
extern int *ObjList_GetObjects(int *startIndex, int *objectCount);
extern int *objFindTexture(int obj, int textureIndex, int materialIndex);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_GetPlayerObject(void);
extern u8 *Obj_AllocObjectSetup(int size, int objectId);
extern int Obj_SetupObject(u8 *setup, int mode, int mapLayer, int objIndex, int parent);
extern void ObjHits_DisableObject(ScTotemBondObject *obj);
extern void ObjHits_EnableObject(ScTotemBondObject *obj);
extern u8 fn_801DD1A8(ScTotemPuzzleObject *obj, ScTotemPuzzleState *state);
extern uint GameBit_Get(int eventId);
extern int GameBit_Set(int eventId, int value);
extern f32 fn_80293E80(f32 angle);
extern f32 sin(f32 angle);
extern int *gObjectTriggerInterface;
extern int *gGameUIInterface;
extern int *gScreenTransitionInterface;
extern int *gCameraInterface;
extern int *gMapEventInterface;
extern u16 lbl_80327A60[];
extern u16 lbl_80327A70[];
extern f32 lbl_803E5640;
extern f32 lbl_803E5644;
extern f32 lbl_803E5638;
extern f32 lbl_803E563C;
extern f32 lbl_803E5654;
extern f32 lbl_803E5658;
extern f32 lbl_803E565C;
extern f32 lbl_803E5660;
extern void hudFn_8011f38c(int visible);
extern void fn_80296124(int player, void *pos, void *obj, int arg);

#define SC_TOTEMPUZZLE_CRYSTAL_OBJECT_TYPE 0x3c1
#define SC_TOTEMPUZZLE_PEER_OBJECT_TYPE 0x282

#define SC_TOTEMPUZZLE_STATE_FLAGS_OFFSET 0x12
#define SC_TOTEMPUZZLE_STATE_STEP_OFFSET 0x10
#define SC_TOTEMPUZZLE_STATE_READY_FLAG 0x2
#define SC_TOTEMPUZZLE_STATE_REVERSED_FLAG 0x1
#define SC_TOTEMPUZZLE_FORWARD_STEP 4
#define SC_TOTEMPUZZLE_REVERSE_STEP 3
#define SC_TOTEMPUZZLE_SOLVED_COUNT 5

#define SC_TOTEMPUZZLE_WRONG_SFX_ID 0x487
#define SC_TOTEMPUZZLE_COMPLETE_SFX_ID 0x7e
#define SC_TOTEMPUZZLE_PROGRESS_SFX_ID 0x409

#define SC_TOTEMBOND_ORB_COUNT 8
#define SC_TOTEMBOND_ORB_SETUP_SIZE 0x38
#define SC_TOTEMBOND_ORB_OBJECT_ID 0x27b
#define SC_TOTEMBOND_ORB_TRIGGER_EVENT 0x64c
#define SC_TOTEMBOND_ORB_ANGLE_STEP 0x2000

/*
 * --INFO--
 *
 * Function: sc_totempuzzle_update
 * EN v1.0 Address: 0x801DD46C
 * EN v1.0 Size: 588b
 * EN v1.1 Address: 0x801DD798
 * EN v1.1 Size: 656b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sc_totempuzzle_update(ScTotemPuzzleObject *obj)
{
  ScTotemPuzzleState *state;
  int hitKind;
  int startIndex;
  int objectCount;
  int *objects;
  int other;
  int *texture;
  f32 lightArgs[6];

  state = obj->state;
  hitKind = ObjHits_GetPriorityHitWithPosition(obj, &lightArgs[0], &lightArgs[1], &lightArgs[2],
                                               &lightArgs[3], &lightArgs[4], &lightArgs[5]);
  if ((obj->puzzleIndex == 5) || (GameBit_Get(0x639) != 0) || (GameBit_Get(0xc10) == 0)) {
    if ((hitKind != 0) && (hitKind != 0x11)) {
      Sfx_PlayFromObject((int)obj, 0x138);
      lightArgs[3] += playerMapOffsetX;
      lightArgs[5] += playerMapOffsetZ;
      objLightFn_8009a1dc((int)obj, lbl_803E5618, lightArgs, 1, 0);
    }
    return;
  }

  if ((hitKind != 0) && (hitKind != 0x11)) {
    Sfx_PlayFromObject((int)obj, 0x138);
    lightArgs[3] += playerMapOffsetX;
    lightArgs[5] += playerMapOffsetZ;
    objLightFn_8009a1dc((int)obj, lbl_803E5618, lightArgs, 1, 0);
    state->flags ^= SC_TOTEMPUZZLE_STATE_READY_FLAG;
    if ((state->flags & SC_TOTEMPUZZLE_STATE_READY_FLAG) != 0) {
      if (state->pulseTimer != lbl_803E55F4) {
        GameBit_Set(0x639, fn_801DD1A8(obj, state));
      }
      objects = ObjList_GetObjects(&startIndex, &objectCount);
      while (startIndex < objectCount) {
        other = objects[startIndex];
        if ((*(s16 *)(other + 0x46) == SC_TOTEMPUZZLE_CRYSTAL_OBJECT_TYPE) &&
            (other != (int)obj)) {
          *(f32 *)(*(int *)(other + 0xb8) + 8) += lbl_803E561C;
        }
        startIndex++;
      }
    } else {
      objects = ObjList_GetObjects(&startIndex, &objectCount);
      while (startIndex < objectCount) {
        other = objects[startIndex];
        if ((*(s16 *)(other + 0x46) == SC_TOTEMPUZZLE_CRYSTAL_OBJECT_TYPE) &&
            (other != (int)obj)) {
          *(f32 *)(*(int *)(other + 0xb8) + 8) += lbl_803E5620;
        }
        startIndex++;
      }
      texture = objFindTexture((int)obj, 0, 0);
      if (texture != NULL) {
        *texture = 0;
      }
    }
  }

  if ((state->flags & SC_TOTEMPUZZLE_STATE_READY_FLAG) != 0) {
    return;
  }

  if ((state->flags & 4) != 0) {
    state->pulseTimer -= timeDelta;
    if (state->pulseTimer < lbl_803E55F4) {
      state->flags &= ~4;
      Sfx_PlayFromObjectLimited((int)obj, 0x137, 2);
      if ((state->flags & SC_TOTEMPUZZLE_STATE_REVERSED_FLAG) != 0) {
        state->stepIndex--;
        if (state->stepIndex < 0) {
          state->angle += lbl_803E5624;
          state->stepIndex = 7;
        }
      } else {
        state->stepIndex++;
        if (state->stepIndex > 7) {
          state->angle -= lbl_803E5624;
          state->stepIndex = 0;
        }
      }
    }
  } else {
    if (((state->flags & SC_TOTEMPUZZLE_STATE_REVERSED_FLAG) != 0) &&
        (state->angle > (lbl_803E55F0 * (f32)(s32)(state->stepIndex + 1)))) {
      state->angle -= lbl_803E5628 * state->peerPhaseOffset * timeDelta;
    } else if (state->angle < (lbl_803E55F0 * (f32)(s32)state->stepIndex)) {
      state->angle += lbl_803E5628 * state->peerPhaseOffset * timeDelta;
    } else {
      state->pulseTimer = state->pulseTimerReset / state->peerPhaseOffset;
      state->flags |= 4;
    }
  }

  obj->yaw = (s16)(s32)state->angle;
}

/*
 * --INFO--
 *
 * Function: FUN_801dd6b8
 * EN v1.0 Address: 0x801DD6B8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801DDA28
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dd6b8(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801dd6e0
 * EN v1.0 Address: 0x801DD6E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801DDA5C
 * EN v1.1 Size: 1048b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dd6e0(undefined2 *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801dd6e4
 * EN v1.0 Address: 0x801DD6E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801DDE74
 * EN v1.1 Size: 420b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dd6e4(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: sc_totembond_spawnGameBitOrbs
 * EN v1.0 Address: 0x801DD6E8
 * EN v1.0 Size: 592b
 * EN v1.1 Address: 0x801DE018
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sc_totembond_spawnGameBitOrbs(ScTotemBondObject *obj,ScTotemBondState *state,f32 radius)
{
  u8 *setup;
  u8 *definition;
  s32 angleOffset;
  s8 orbIndex;
  s8 i;
  f32 angleScale;
  f32 angleDivisor;

  if (Obj_IsLoadingLocked() != 0) {
    i = 0;
    orbIndex = 1;
    angleOffset = 0;
    angleScale = lbl_803E5640;
    angleDivisor = lbl_803E5644;
    while (i < SC_TOTEMBOND_ORB_COUNT) {
      definition = obj->definition;
      setup = Obj_AllocObjectSetup(SC_TOTEMBOND_ORB_SETUP_SIZE,SC_TOTEMBOND_ORB_OBJECT_ID);
      *(f32 *)(setup + 0x08) = radius * fn_80293E80(
          (angleScale * (f32)(s32)(obj->yaw + angleOffset)) / angleDivisor) + obj->x;
      *(f32 *)(setup + 0x0c) = obj->y;
      *(f32 *)(setup + 0x10) = radius * sin(
          (angleScale * (f32)(s32)(obj->yaw + angleOffset)) / angleDivisor) + obj->z;
      setup[0x04] = definition[0x04];
      setup[0x05] = (definition[0x05] & ~1) | 4;
      setup[0x06] = definition[0x06];
      setup[0x07] = 0x1e;
      *(s16 *)(setup + 0x18) = -1;
      *(s16 *)(setup + 0x1a) = SC_TOTEMBOND_ORB_TRIGGER_EVENT;
      *(s16 *)(setup + 0x1c) = (s16)lbl_80327A70[(s8)orbIndex];
      *(s16 *)(setup + 0x30) = (s16)lbl_80327A60[(s8)orbIndex];
      *(s8 *)(setup + 0x2a) = (s8)(((obj->yaw + 0x8000) + angleOffset) >> 8);
      setup[0x32] = 1;
      Obj_SetupObject(setup,5,-1,-1,0);
      orbIndex++;
      if (orbIndex > 7) {
        orbIndex = 0;
      }
      angleOffset += SC_TOTEMBOND_ORB_ANGLE_STEP;
      i++;
    }
  }
}

/*
 * --INFO--
 *
 * Function: sc_totempuzzle_processAnimEvents
 * EN v1.0 Address: 0x801DD938
 * EN v1.0 Size: 468b
 * EN v1.1 Address: 0x801DE210
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 sc_totempuzzle_processAnimEvents(ScTotemBondObject *obj,undefined4 param_2,ObjAnimUpdateState *animUpdate)
{
  ScTotemBondState *state;
  int startForEvent3;
  int countForEvent3;
  int startForEvent2;
  int countForEvent2;
  int *objects;
  int *objectPtr;
  int peer;
  int eventIndex;
  int eventId;

  state = obj->state;
  animUpdate->sequenceEventActive = 0;
  for (eventIndex = 0; eventIndex < animUpdate->eventCount; eventIndex++) {
    eventId = animUpdate->eventIds[eventIndex];
    switch (eventId) {
    case 1:
      state->eventFlags |= 1;
      (*(code *)(*gObjectTriggerInterface + 0x50))(0x44,1,0,0);
      break;
    case 2:
      objects = ObjList_GetObjects(&startForEvent2,&countForEvent2);
      objectPtr = objects + startForEvent2;
      while (startForEvent2 < countForEvent2) {
        peer = *objectPtr;
        if (((ScTotemBondObject *)peer != obj) &&
            (*(s16 *)(peer + 0x46) == SC_TOTEMPUZZLE_PEER_OBJECT_TYPE)) {
          peer = objects[startForEvent2];
          (*(code *)(**(int **)(peer + 0x68) + 0x20))(peer,2);
          break;
        }
        objectPtr++;
        startForEvent2++;
      }
      state->eventFlags |= 0x10;
      break;
    case 3:
      objects = ObjList_GetObjects(&startForEvent3,&countForEvent3);
      objectPtr = objects + startForEvent3;
      while (startForEvent3 < countForEvent3) {
        peer = *objectPtr;
        if (((ScTotemBondObject *)peer != obj) &&
            (*(s16 *)(peer + 0x46) == SC_TOTEMPUZZLE_PEER_OBJECT_TYPE)) {
          peer = objects[startForEvent3];
          (*(code *)(**(int **)(peer + 0x68) + 0x20))(peer,1);
          break;
        }
        objectPtr++;
        startForEvent3++;
      }
      break;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801ddb0c
 * EN v1.0 Address: 0x801DDB0C
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x801DE3F4
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ddb0c(void)
{
  FUN_800067c0((int *)0xf0,0);
  FUN_8011eb10(0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ddb3c
 * EN v1.0 Address: 0x801DDB3C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801DE424
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ddb3c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void sc_totempuzzle_release(void) {}
void sc_totempuzzle_initialise(void) {}

extern s16 lbl_80327A18[];
extern f32 lbl_803E55FC;
extern f32 lbl_803E562C;
extern f32 lbl_803E5630;
extern void fn_801DD170(int obj);
extern int *objFindTexture(int obj, int a, int b);
extern uint GameBit_Get(int eventId);
extern int randomGetRange(int lo, int hi);

#pragma peephole off
#pragma scheduling off
void sc_totempuzzle_init(ScTotemPuzzleObject *obj, ScTotemPuzzleMapData *params) {
    ScTotemPuzzleState *state;
    int *tex;
    int r;
    f32 fz;

    state = obj->state;
    obj->puzzleIndex = (s8)params->puzzleIndex;
    if (obj->puzzleIndex < 0 || obj->puzzleIndex > 5) {
        obj->puzzleIndex = 0;
    }
    if (obj->puzzleIndex == 5) {
        tex = (int*)objFindTexture((int)obj, 0, 0);
        if (tex != NULL) {
            *tex = 0x100;
        }
    }
    state->stepIndex = (s16)obj->puzzleIndex;
    if (GameBit_Get(0x639) == 0) {
        state->angle = (f32)(s32)lbl_80327A18[state->stepIndex];
    } else {
        state->angle = lbl_803E562C;
        tex = (int*)objFindTexture((int)obj, 0, 0);
        if (tex != NULL) {
            *tex = 0x100;
        }
    }
    obj->yaw = (s16)(s32)state->angle;
    r = randomGetRange(7, 10);
    fz = (f32)r * lbl_803E5630;
    state->pulseTimerReset = fz;
    state->pulseTimer = fz;
    if (obj->puzzleIndex & 1) {
        state->flags = 1;
    }
    state->peerPhaseOffset = lbl_803E55FC;
    obj->animEventCallback = fn_801DD170;
    obj->objectFlags = (u16)(obj->objectFlags | 0x6000);
}
#pragma scheduling reset
#pragma peephole reset
void sc_totembond_hitDetect(void) {}
void sc_totembond_release(void) {}
void sc_totembond_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int sc_totembond_getExtraSize(void) { return 0x28; }
int sc_totembond_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5650;
extern void objRenderFn_8003b8f4(f32);
#pragma peephole off
void sc_totembond_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5650); }
#pragma peephole reset

extern void Music_Trigger(int track, int param);
extern void fn_8011F6D4(int p);
#pragma scheduling off
void sc_totembond_free(int obj) {
    Music_Trigger(240, 0);
    fn_8011F6D4(0);
}
#pragma scheduling reset

#pragma dont_inline on
void sc_totembond_update(ScTotemBondObject *obj)
{
    ScTotemBondState *state;
    int player;
    u8 availableOrbs[8];
    u8 availableCount;
    u8 orbIndex;
    u8 nextRing;
    u8 allOrbsCollected;

    state = obj->state;
    player = Obj_GetPlayerObject();
    if ((state->eventFlags & 1) != 0) {
        state->active = 1;
        obj->yaw = 0x3fff;
        state->ringIndex = (s16)(u16)((s32)obj->yaw / SC_TOTEMBOND_ORB_ANGLE_STEP);
        ObjHits_DisableObject(obj);
        sc_totembond_spawnGameBitOrbs(obj,state,lbl_803E5638);
        GameBit_Set(lbl_80327A60[state->ringIndex],1);
        obj->mapAlpha = 0;
        state->eventFlags &= ~1;
        state->eventFlags |= 2;
        (*(code *)(*gGameUIInterface + 0x40))(1);
        hudFn_8011f38c(1);
        (*(code *)(*gScreenTransitionInterface + 0x0c))(0x1e,1);
        state->spawnTimer = lbl_803E563C;
        Music_Trigger(0xf0,1);
    }

    if ((state->eventFlags & 2) != 0) {
        if (state->spawnTimer != lbl_803E5654) {
            state->spawnTimer -= timeDelta;
            if (state->spawnTimer < lbl_803E5654) {
                state->spawnTimer = lbl_803E5654;
            }
        } else if (state->completionTimer != lbl_803E5654) {
            state->completionTimer -= timeDelta;
            if (state->completionTimer <= lbl_803E5654) {
                state->completionTimer = lbl_803E5654;
                player = Obj_GetPlayerObject();
                (*(code *)(*gMapEventInterface + 0x2c))();
                (*(code *)(*gCameraInterface + 0x1c))(0x42,0,3,0,0,0,0);
                obj->mapAlpha = 0xff;
                fn_80296124(player,NULL,NULL,0);
                ObjHits_EnableObject(obj);
                hudFn_8011f38c(0);
                GameBit_Set(0x2bc,1);
                state->eventFlags = 0;
                Music_Trigger(0xf0,0);
                return;
            }
        } else {
            if (GameBit_Get(SC_TOTEMBOND_ORB_TRIGGER_EVENT) != 0) {
                GameBit_Set(SC_TOTEMBOND_ORB_TRIGGER_EVENT,0);
                availableCount = 0;
                for (orbIndex = 0; orbIndex < SC_TOTEMBOND_ORB_COUNT; orbIndex++) {
                    if (GameBit_Get(lbl_80327A70[orbIndex]) == 0) {
                        availableOrbs[availableCount++] = orbIndex;
                    }
                }
                if (availableCount == 0) {
                    allOrbsCollected = 1;
                } else {
                    nextRing = availableOrbs[randomGetRange(0,availableCount - 1)];
                    if (state->ringIndex == nextRing) {
                        GameBit_Set(lbl_80327A60[state->ringIndex],1);
                    }
                    if (state->ringIndex != nextRing) {
                        state->ringIndex = nextRing;
                        Sfx_PlayFromObject((int)obj,0x137);
                    }
                    allOrbsCollected = 0;
                }
                if (allOrbsCollected) {
                    state->completionTimer = lbl_803E5658;
                    fn_8011F6D4(0);
                    (*(code *)(*gScreenTransitionInterface + 0x08))(0x1e,1);
                }
            }
            if (((u32)(u16)obj->yaw >> 13) != state->ringIndex) {
                obj->yaw = (s32)-((lbl_803E565C * timeDelta) - (f32)(s32)obj->yaw);
                if (((u32)(u16)obj->yaw >> 13) == state->ringIndex) {
                    GameBit_Set(lbl_80327A60[state->ringIndex],1);
                }
            }
        }

        fn_80296124(player,&obj->x,obj,0);
        state->x = obj->x;
        state->y = lbl_803E563C + obj->y;
        state->z = obj->z;
        state->yaw = (s16)(0x8000 - obj->yaw);
        state->pitch = obj->pitch;
        state->roll = obj->roll;
        state->cameraDistance = lbl_803E5660;
        (*(code *)(*gCameraInterface + 0x60))(state,0x18);
    }

    if ((state->eventFlags & 0x10) != 0) {
        ((MapEventInterface *)*gMapEventInterface)->setMode(0xe, 6);
        state->eventFlags &= ~0x10;
    }
}
#pragma dont_inline reset

#pragma scheduling off
#pragma peephole off
void sc_totembond_init(ScTotemBondObject *obj, int params) {
    ScTotemBondState *state;
    u32 v;
    s16 hi = (s16)(u16)((s32)obj->yaw / 8192);
    state = obj->state;
    state->ringIndex = hi;
    obj->animEventCallback = sc_totempuzzle_processAnimEvents;
    v = (u32)obj->objectFlags | 0x6000;
    obj->objectFlags = (u16)v;
}
#pragma peephole reset
#pragma scheduling reset

int fn_801DE320(u16 *gameBitIds,u16 newValue)
{
    u16 values[4];
    int changed;
    u8 readIndex;
    u8 pass;
    u8 sortIndex;
    u8 writeIndex;
    u16 current;
    u16 next;

    changed = 0;
    for (readIndex = 0; readIndex < 3; readIndex++) {
        values[readIndex] = (u16)GameBit_Get(gameBitIds[readIndex]);
    }
    values[3] = newValue;

    for (pass = 0; pass < 3; pass++) {
        for (sortIndex = 0; sortIndex < 3; sortIndex++) {
            next = values[sortIndex + 1];
            if (next != 0) {
                current = values[sortIndex];
                if ((next < current) || (current == 0)) {
                    values[sortIndex] = next;
                    values[sortIndex + 1] = current;
                    changed = 1;
                }
            }
        }
    }

    for (writeIndex = 0; writeIndex < 3; writeIndex++) {
        GameBit_Set(gameBitIds[writeIndex],values[writeIndex]);
    }
    return changed;
}
