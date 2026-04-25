#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"
#include "main/unknown/autos/placeholder_8002F604.h"

extern undefined4 FUN_800723a0();
extern void fn_80024E7C(int animId,int moveIndex,undefined4 cache,ObjAnimDef *animDef);

extern char gObjAnimSetBlendMoveMissingAnimWarning[];
extern f64 DOUBLE_803df568;
extern f64 DOUBLE_803df580;
extern f32 FLOAT_803df560;
extern f32 FLOAT_803df570;
extern f32 FLOAT_803df574;
extern f32 FLOAT_803df578;
extern f32 FLOAT_803df588;

static inline s32 ObjAnim_ResolveMoveIndex(ObjAnimDef *animDef, u32 moveId) {
  s32 moveIndex = animDef->moveBaseTable[(s32)moveId >> 8] + (moveId & 0xFF);

  if (animDef->moveCount <= moveIndex) {
    moveIndex = animDef->moveCount - 1;
  }
  if (moveIndex < 0) {
    moveIndex = 0;
  }
  return moveIndex;
}

static inline f64 ObjAnim_U32AsDouble(u32 value) {
  u64 bits = CONCAT44(0x43300000, value);
  return *(f64 *)&bits;
}

/*
 * --INFO--
 *
 * Function: ObjAnim_SetBlendMove
 * EN v1.0 Address: 0x8002EBA8
 * EN v1.0 Size: 540b
 * EN v1.1 Address: 0x8002EC4C
 * EN v1.1 Size: 452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma dont_inline on
void ObjAnim_SetBlendMove(int objAnim,ObjAnimDef *animDef,ObjAnimState *state,uint moveId,s16 eventState)
{
  float frameValue;
  uint frameType;
  int moveData;
  int moveIndex;
  u64 frameBits;

  moveIndex = animDef->moveBaseTable[(s32)moveId >> 8] + (moveId & 0xff);
  if (animDef->moveCount <= moveIndex) {
    moveIndex = animDef->moveCount - 1;
  }
  if (moveIndex < 0) {
    moveIndex = 0;
  }
  if ((animDef->flags & 0x40) != 0) {
    if (state->lastBlendMoveIndex != moveIndex) {
      state->blendCacheSlot = (u16)state->blendToggle;
      state->prevBlendCacheSlot = (u16)(1 - state->blendToggle);
      if (animDef->blendMoveIds[moveIndex] == -1) {
        OSReport(gObjAnimSetBlendMoveMissingAnimWarning,animDef->modNo);
        moveIndex = 0;
      }
      fn_80024E7C((int)animDef->blendMoveIds[moveIndex],(int)(s16)moveIndex,
                  (undefined4)state->blendMoveCache[state->blendCacheSlot],animDef);
      state->lastBlendMoveIndex = (s16)moveIndex;
    }
    moveData = (int)state->blendMoveCache[state->blendCacheSlot] + 0x80;
  }
  else {
    state->blendCacheSlot = (u16)moveIndex;
    moveData = (int)animDef->moveData[state->blendCacheSlot];
  }
  state->frameCmd = (u8 *)(moveData + 6);
  frameType = *(u8 *)(moveData + 1) & 0xf0;
  if (frameType != state->frameType) {
    state->eventState = 0;
  }
  else {
    frameBits = CONCAT44(0x43300000, (uint)state->frameCmd[1]);
    frameValue = (float)(*(f64 *)&frameBits - DOUBLE_803df568);
    if (frameType == 0) {
      frameValue = frameValue - FLOAT_803df560;
    }
    if (frameValue != state->segmentLength) {
      state->eventState = 0;
    }
    else {
      state->eventState = eventState;
    }
  }
  return;
}
#pragma dont_inline reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: Object_ObjAnimSetPrimaryBlendMove
 * EN v1.0 Address: 0x8002EDC4
 * EN v1.0 Size: 568b
 * EN v1.1 Address: 0x8002EE10
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void Object_ObjAnimSetPrimaryBlendMove(int objAnim,uint moveId,int eventState)
{
  ObjAnimBank *bank;

  bank = ObjAnim_GetActiveBank((ObjAnimComponent *)objAnim);
  if (bank->animDef->moveCount != 0) {
    ObjAnim_SetBlendMove(objAnim,bank->animDef,bank->primaryState,moveId,eventState);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: Object_ObjAnimSetSecondaryBlendMove
 * EN v1.0 Address: 0x8002EFFC
 * EN v1.0 Size: 568b
 * EN v1.1 Address: 0x8002EE64
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void Object_ObjAnimSetSecondaryBlendMove(int objAnim,uint moveId,int eventState)
{
  ObjAnimBank *bank;

  bank = ObjAnim_GetActiveBank((ObjAnimComponent *)objAnim);
  if (bank->animDef->moveCount != 0) {
    ObjAnim_SetBlendMove(objAnim,bank->animDef,bank->secondaryState,moveId,eventState);
  }
  return;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: Object_ObjAnimAdvanceMove
 * EN v1.0 Address: 0x8002F234
 * EN v1.0 Size: 1168b
 * EN v1.1 Address: 0x8002EEB8
 * EN v1.1 Size: 1100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 Object_ObjAnimAdvanceMove(f32 moveStepScale,f32 deltaTime,int objAnimArg,int eventsArg)
{
  ObjAnimComponent *objAnim;
  ObjAnimEventList *events;
  ObjAnimBank *bank;
  ObjAnimState *state;
  int iVar1;
  int iVar2;
  char cVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  undefined4 uVar7;
  uint uVar8;
  int iVar9;
  int eventCountdown;
  int *piVar10;
  int iVar11;
  int iVar12;
  byte bVar13;
  uint uVar14;
  undefined uVar15;
  double local_28;

  objAnim = (ObjAnimComponent *)objAnimArg;
  events = (ObjAnimEventList *)eventsArg;
  uVar7 = 0;
  bank = ObjAnim_GetActiveBank(objAnim);
  piVar10 = (int *)bank;
  if (bank->animDef->moveCount == 0) {
    uVar7 = 0;
  }
  else {
    state = bank->primaryState;
    iVar11 = (int)state;
    state->step = moveStepScale * state->segmentLength;
    if (state->eventCountdown != 0) {
      if ((state->flags & 8) != 0) {
        state->savedStep = state->step;
      }
      state->progress = state->savedStep * deltaTime + state->progress;
      fVar5 = FLOAT_803df570;
      fVar4 = state->prevSegmentLength;
      if (state->prevFrameType == 0) {
        fVar5 = state->progress;
        fVar6 = FLOAT_803df570;
        if ((FLOAT_803df570 <= fVar5) && (fVar6 = fVar5, fVar4 < fVar5)) {
          fVar6 = fVar4;
        }
        state->progress = fVar6;
      }
      else {
        if (state->progress < FLOAT_803df570) {
          while (state->progress < fVar5) {
            state->progress = state->progress + fVar4;
          }
        }
        if (fVar4 <= state->progress) {
          while (fVar4 <= state->progress) {
            state->progress = state->progress - fVar4;
          }
        }
      }
      if ((state->flags & 2) == 0) {
        eventCountdown =
            (int)-(float)((double)(float)(ObjAnim_U32AsDouble((uint)state->eventStep) -
                                          DOUBLE_803df568) *
                              deltaTime -
                          (double)(float)(ObjAnim_U32AsDouble(state->eventCountdown ^ 0x80000000) -
                                          DOUBLE_803df580));
        fVar4 = FLOAT_803df570;
        if ((-1 < eventCountdown) &&
           (eventCountdown = eventCountdown ^ 0x80000000, fVar4 = FLOAT_803df574,
           (float)(ObjAnim_U32AsDouble(eventCountdown) - DOUBLE_803df580) <= FLOAT_803df574)) {
          local_28 = ObjAnim_U32AsDouble(eventCountdown);
          fVar4 = (float)(local_28 - DOUBLE_803df580);
        }
        state->eventCountdown = (u16)(int)fVar4;
      }
      if (state->eventCountdown == 0) {
        state->prevEventState = 0;
      }
    }
    fVar4 = objAnim->moveProgress;
    objAnim->moveProgress = fVar4 + moveStepScale * deltaTime;
    fVar6 = FLOAT_803df570;
    fVar5 = FLOAT_803df560;
    if (objAnim->moveProgress < FLOAT_803df560) {
      if (objAnim->moveProgress < FLOAT_803df570) {
        if (state->frameType == 0) {
          objAnim->moveProgress = FLOAT_803df570;
        }
        else {
          while (objAnim->moveProgress < fVar6) {
            objAnim->moveProgress = objAnim->moveProgress + fVar5;
          }
        }
        uVar7 = 1;
      }
    }
    else {
      if (state->frameType == 0) {
        objAnim->moveProgress = FLOAT_803df560;
      }
      else {
        while (fVar5 <= objAnim->moveProgress) {
          objAnim->moveProgress = objAnim->moveProgress - fVar5;
        }
      }
      uVar7 = 1;
    }
    if ((events != (ObjAnimEventList *)0) && (events->resetFlag = 0, objAnim->eventTable != 0)) {
      events->count = 0;
      iVar11 = **(int **)objAnim->eventTable >> 1;
      if (iVar11 != 0) {
        iVar1 = (int)(FLOAT_803df578 * fVar4);
        iVar2 = (int)(FLOAT_803df578 * objAnim->moveProgress);
        bVar13 = iVar2 < iVar1;
        if (moveStepScale * deltaTime < FLOAT_803df570) {
          bVar13 = bVar13 | 2;
        }
        iVar12 = 0;
        iVar9 = 0;
        while ((iVar12 < iVar11 && (events->count < 8))) {
          uVar14 = (uint)*(short *)(*(int *)(*(int *)objAnim->eventTable + 4) + iVar9);
          uVar8 = uVar14 & 0x1ff;
          uVar14 = uVar14 >> 9 & 0x7f;
          if (uVar14 != 0x7f) {
            uVar15 = (undefined)uVar14;
            if (((bVar13 == 0) && (iVar1 <= (int)uVar8)) && ((int)uVar8 < iVar2)) {
              cVar3 = events->count;
              events->count = cVar3 + '\x01';
              events->triggeredIds[(u8)cVar3] = uVar15;
            }
            if ((bVar13 == 1) && ((iVar1 <= (int)uVar8 || ((int)uVar8 < iVar2)))) {
              cVar3 = events->count;
              events->count = cVar3 + '\x01';
              events->triggeredIds[(u8)cVar3] = uVar15;
            }
            if (((bVar13 == 3) && (iVar2 < (int)uVar8)) && ((int)uVar8 <= iVar1)) {
              cVar3 = events->count;
              events->count = cVar3 + '\x01';
              events->triggeredIds[(u8)cVar3] = uVar15;
            }
            if ((bVar13 == 2) && ((iVar2 < (int)uVar8 || ((int)uVar8 <= iVar1)))) {
              cVar3 = events->count;
              events->count = cVar3 + '\x01';
              events->triggeredIds[(u8)cVar3] = uVar15;
            }
          }
          iVar9 = iVar9 + 2;
          iVar12 = iVar12 + 1;
        }
      }
    }
  }
  return uVar7;
}

/*
 * --INFO--
 *
 * Function: Object_ObjAnimSetMoveProgress
 * EN v1.0 Address: 0x8002F6C4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8002F304
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 Object_ObjAnimSetMoveProgress(f32 param_1,int param_2)
{
  ObjAnimComponent *objAnim;

  objAnim = (ObjAnimComponent *)param_2;
  if (param_1 > FLOAT_803df588) {
    param_1 = FLOAT_803df588;
  }
  else if (param_1 < FLOAT_803df570) {
    param_1 = FLOAT_803df570;
  }
  objAnim->moveProgress = param_1;
  return 0;
}

/*
 * --INFO--
 *
 * Function: Object_ObjAnimSetMove
 * EN v1.0 Address: 0x8002F6F8
 * EN v1.0 Size: 816b
 * EN v1.1 Address: 0x8002F334
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
undefined4
Object_ObjAnimSetMove(f32 moveProgress,int objAnimArg,uint moveId,undefined flags)
{
  ObjAnimComponent *objAnim;
  ObjAnimBank *bank;
  ObjAnimDef *animDef;
  ObjAnimState *state;
  short sVar1;
  uint uVar2;
  int iVar3;
  int iVar6;
  float clampedProgress;
  objAnim = (ObjAnimComponent *)objAnimArg;
  clampedProgress = moveProgress;
  if (clampedProgress > FLOAT_803df560) {
    clampedProgress = FLOAT_803df560;
  }
  else if (clampedProgress < FLOAT_803df570) {
    clampedProgress = FLOAT_803df570;
  }
  objAnim->moveProgress = clampedProgress;
  bank = ObjAnim_GetActiveBank(objAnim);
  animDef = bank->animDef;
  if (animDef->moveCount != 0) {
    state = bank->primaryState;
    state->flags = flags;
    state->prevMoveCacheSlot = state->moveCacheSlot;
    state->progress = state->speed;
    state->prevSegmentLength = state->segmentLength;
    state->savedStep = state->step;
    state->prevFrameData = state->frameData;
    state->prevFrameType = state->frameType;
    state->prevBlendCacheSlot = state->blendCacheSlot;
    state->prevFrameCmd = state->frameCmd;
    state->prevEventState = state->eventState;
    state->eventState = 0;
    state->lastBlendMoveIndex = -1;
    sVar1 = objAnim->activeMove;
    objAnim->activeMove = (s16)moveId;
    iVar3 = ObjAnim_ResolveMoveIndex(animDef, moveId);
    if ((animDef->flags & 0x40) != 0) {
      if (moveId != sVar1) {
        state->blendToggle = '\x01' - state->blendToggle;
        state->moveCacheSlot = (u16)state->blendToggle;
        if (animDef->blendMoveIds[iVar3] == -1) {
          OSReport(gObjAnimSetBlendMoveMissingAnimWarning,animDef->modNo);
          iVar3 = 0;
        }
        fn_80024E7C((int)animDef->blendMoveIds[iVar3],(int)(s16)iVar3,
                    (undefined4)state->moveCache[state->moveCacheSlot],animDef);
      }
      iVar6 = (int)state->moveCache[state->moveCacheSlot] + 0x80;
    }
    else {
      state->moveCacheSlot = (u16)iVar3;
      iVar6 = (int)animDef->moveData[state->moveCacheSlot];
    }
    state->frameData = (u8 *)(iVar6 + 6);
    state->frameType = *(u8 *)(iVar6 + 1) & 0xf0;
    state->segmentLength =
         (float)(ObjAnim_U32AsDouble((uint)state->frameData[1]) - DOUBLE_803df568);
    if (state->frameType == 0) {
      state->segmentLength = state->segmentLength - FLOAT_803df560;
    }
    uVar2 = *(u8 *)(iVar6 + 1) & 0xf;
    if (uVar2 != 0) {
      state->savedStep = state->step;
      state->eventStep =
           (short)(int)(FLOAT_803df574 /
                        (float)(ObjAnim_U32AsDouble(uVar2 ^ 0x80000000) - DOUBLE_803df580));
      state->eventCountdown = 0x4000;
    }
    state->step = FLOAT_803df570;
    state->speed = clampedProgress * state->segmentLength;
  }
  return 0;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjAnim_GetPrimaryEventCountdown
 * EN v1.0 Address: 0x8002F50C
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8002F604
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
undefined2 ObjAnim_GetPrimaryEventCountdown(int objAnim)
{
  return ObjAnim_GetSecondaryState((ObjAnimComponent *)objAnim)->eventCountdown;
}

/*
 * --INFO--
 *
 * Function: ObjAnim_WriteStateWord
 * EN v1.0 Address: 0x8002F52C
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x8002F624
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjAnim_WriteStateWord(int objAnim,int stateIndex,short wordIndex,int value)
{
  ObjAnimBank *bank;
  ObjAnimState *state;
  u16 stateWord;

  bank = ObjAnim_GetActiveBank((ObjAnimComponent *)objAnim);
  if (bank == (ObjAnimBank *)0x0) {
    return;
  }
  stateWord = value;
  if (stateIndex != 0) {
    state = bank->primaryState;
  }
  else {
    state = bank->secondaryState;
  }
  state = (ObjAnimState *)((u8 *)state + wordIndex * 2);
  state->eventCountdown = stateWord;
}

/*
 * --INFO--
 *
 * Function: ObjAnim_SetPrimaryEventStepFrames
 * EN v1.0 Address: 0x8002F574
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x8002F66C
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjAnim_SetPrimaryEventStepFrames(int objAnim,uint frameCount)
{
  ObjAnimBank *bank;
  u32 biasedFrameCount;

  bank = ObjAnim_GetActiveBank((ObjAnimComponent *)objAnim);
  if (bank != (ObjAnimBank *)0x0) {
    biasedFrameCount = frameCount ^ 0x80000000;
    bank->secondaryState->eventStep =
        (short)(int)(FLOAT_803df574 /
                    (float)(ObjAnim_U32AsDouble(biasedFrameCount) - DOUBLE_803df580));
  }
}
#pragma scheduling reset
