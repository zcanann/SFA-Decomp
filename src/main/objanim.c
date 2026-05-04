#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/objHitReact.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"

extern undefined4 FUN_800723a0();
extern void ObjAnim_LoadCachedMove(int animId,int moveIndex,u8 *cache,ObjAnimDef *animDef);
extern void ObjAnim_LoadMoveEvents(int objAnim,int objType,ObjAnimEventTable *eventTable,u32 moveId,
                                   int async);
extern void ObjHitReact_LoadMoveEntries(int objAnim,ObjAnimBank *bank,int objType,
                                        ObjHitReactState *hitState,u32 moveId,int async);

extern char gObjAnimSetBlendMoveMissingAnimWarning[];
extern f64 lbl_803DE8E8;
extern f64 lbl_803DE900;
extern f32 lbl_803DE8E0;
extern f32 lbl_803DE8F0;
extern f32 lbl_803DE8F4;
extern f32 lbl_803DE8F8;
extern f32 lbl_803DE908;
extern f32 lbl_803DE90C;

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
#pragma peephole off
#pragma dont_inline on
void ObjAnim_SetBlendMove(ObjAnimComponent *objAnim,ObjAnimDef *animDef,ObjAnimState *state,
                          uint moveId,s16 eventState)
{
  float frameValue;
  int frameType;
  int moveData;
  int moveIndex;
  u64 frameBits;

  moveIndex = ObjAnim_ResolveMoveIndex(animDef,moveId);
  if ((animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) != 0) {
    if (state->lastBlendMoveIndex != moveIndex) {
      state->blendCacheSlot = (u16)state->blendToggle;
      state->prevBlendCacheSlot = (u16)(1 - state->blendToggle);
      if (animDef->blendMoveIds[moveIndex] == -1) {
        OSReport(gObjAnimSetBlendMoveMissingAnimWarning,animDef->modNo);
        moveIndex = 0;
      }
      ObjAnim_LoadCachedMove((int)animDef->blendMoveIds[moveIndex],(int)(s16)moveIndex,
                             state->blendMoveCache[state->blendCacheSlot],animDef);
      state->lastBlendMoveIndex = (s16)moveIndex;
    }
    moveData = (int)state->blendMoveCache[state->blendCacheSlot] + OBJANIM_CACHED_MOVE_DATA_OFFSET;
  }
  else {
    state->blendCacheSlot = (u16)moveIndex;
    moveData = (int)animDef->moveData[state->blendCacheSlot];
  }
  state->frameCmd = (u8 *)(moveData + OBJANIM_FRAME_CMD_OFFSET);
  frameType = *(s8 *)(moveData + 1) & OBJANIM_FRAME_TYPE_MASK;
  if (frameType != state->frameType) {
    state->eventState = 0;
  }
  else {
    frameBits = CONCAT44(0x43300000, (uint)state->frameCmd[1]);
    frameValue = *(f64 *)&frameBits - lbl_803DE8E8;
    if (frameType == 0) {
      frameValue = frameValue - lbl_803DE8E0;
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
#pragma peephole reset
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
#pragma peephole off
void Object_ObjAnimSetPrimaryBlendMove(ObjAnimComponent *objAnim,uint moveId,int eventState)
{
  ObjAnimBank *bank;

  bank = ObjAnim_GetActiveBank(objAnim);
  if (bank->animDef->moveCount != 0) {
    ObjAnim_SetBlendMove(objAnim,bank->animDef,bank->activeState,moveId,eventState);
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
void Object_ObjAnimSetSecondaryBlendMove(ObjAnimComponent *objAnim,uint moveId,int eventState)
{
  ObjAnimBank *bank;

  bank = ObjAnim_GetActiveBank(objAnim);
  if (bank->animDef->moveCount != 0) {
    ObjAnim_SetBlendMove(objAnim,bank->animDef,bank->currentState,moveId,eventState);
  }
  return;
}
#pragma peephole reset
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
#pragma scheduling off
#pragma peephole off
undefined4 Object_ObjAnimAdvanceMove(f32 moveStepScale,f32 deltaTime,int objAnimArg,int eventsArg)
{
  ObjAnimComponent *objAnim;
  ObjAnimEventList *events;
  ObjAnimEventTable *eventTable;
  ObjAnimBank *bank;
  ObjAnimState *state;
  int iVar1;
  int iVar2;
  char cVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  undefined4 uVar7;
  int iVar9;
  int eventCountdown;
  int *piVar10;
  int iVar11;
  int iVar12;
  byte bVar13;
  u16 eventWord;
  u8 eventId;
  u16 eventFrame;
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
    state = bank->activeState;
    iVar11 = (int)state;
    state->step = moveStepScale * state->segmentLength;
    if (state->eventCountdown != 0) {
      if ((state->flags & 8) != 0) {
        state->savedStep = state->step;
      }
      state->progress = state->savedStep * deltaTime + state->progress;
      fVar5 = lbl_803DE8F0;
      fVar4 = state->prevSegmentLength;
      if (state->prevFrameType == 0) {
        fVar5 = state->progress;
        fVar6 = lbl_803DE8F0;
        if ((lbl_803DE8F0 <= fVar5) && (fVar6 = fVar5, fVar4 < fVar5)) {
          fVar6 = fVar4;
        }
        state->progress = fVar6;
      }
      else {
        if (state->progress < lbl_803DE8F0) {
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
            (int)-(float)((ObjAnim_U32AsDouble((uint)state->eventStep) -
                           lbl_803DE8E8) *
                              deltaTime -
                          (ObjAnim_U32AsDouble(state->eventCountdown ^ 0x80000000) -
                           lbl_803DE900));
        fVar4 = lbl_803DE8F0;
        if ((-1 < eventCountdown) &&
           (eventCountdown = eventCountdown ^ 0x80000000, fVar4 = lbl_803DE8F4,
           ObjAnim_U32AsDouble(eventCountdown) - lbl_803DE900 <= lbl_803DE8F4)) {
          local_28 = ObjAnim_U32AsDouble(eventCountdown);
          fVar4 = local_28 - lbl_803DE900;
        }
        state->eventCountdown = (u16)(int)fVar4;
      }
      if (state->eventCountdown == 0) {
        state->prevEventState = 0;
      }
    }
    fVar4 = objAnim->activeMoveProgress;
    objAnim->activeMoveProgress = fVar4 + moveStepScale * deltaTime;
    fVar6 = lbl_803DE8F0;
    fVar5 = lbl_803DE8E0;
    if (objAnim->activeMoveProgress < lbl_803DE8E0) {
      if (objAnim->activeMoveProgress < lbl_803DE8F0) {
        if (state->frameType == 0) {
          objAnim->activeMoveProgress = lbl_803DE8F0;
        }
        else {
          while (objAnim->activeMoveProgress < fVar6) {
            objAnim->activeMoveProgress = objAnim->activeMoveProgress + fVar5;
          }
        }
        uVar7 = 1;
      }
    }
    else {
      if (state->frameType == 0) {
        objAnim->activeMoveProgress = lbl_803DE8E0;
      }
      else {
        while (fVar5 <= objAnim->activeMoveProgress) {
          objAnim->activeMoveProgress = objAnim->activeMoveProgress - fVar5;
        }
      }
      uVar7 = 1;
    }
    if ((events != (ObjAnimEventList *)0) && (events->resetFlag = 0, objAnim->eventTable != 0)) {
      eventTable = objAnim->eventTable;
      events->triggerCount = 0;
      iVar11 = eventTable->byteCount >> 1;
      if (iVar11 != 0) {
        iVar1 = (int)(lbl_803DE8F8 * fVar4);
        iVar2 = (int)(lbl_803DE8F8 * objAnim->activeMoveProgress);
        bVar13 = iVar2 < iVar1;
        if (moveStepScale * deltaTime < lbl_803DE8F0) {
          bVar13 = bVar13 | 2;
        }
        iVar12 = 0;
        iVar9 = 0;
        while ((iVar12 < iVar11 && (events->triggerCount < OBJANIM_EVENT_TRIGGER_CAPACITY))) {
          eventWord = *(s16 *)((u8 *)eventTable->entries + iVar9);
          eventFrame = eventWord & OBJANIM_EVENT_FRAME_MASK;
          eventId = eventWord >> OBJANIM_EVENT_ID_SHIFT & OBJANIM_EVENT_ID_MASK;
          if (eventId != OBJANIM_EVENT_ID_NONE) {
            if (((bVar13 == 0) && (iVar1 <= (int)eventFrame)) && ((int)eventFrame < iVar2)) {
              cVar3 = events->triggerCount;
              events->triggerCount = cVar3 + '\x01';
              events->triggeredIds[(u8)cVar3] = eventId;
            }
            if ((bVar13 == 1) && ((iVar1 <= (int)eventFrame || ((int)eventFrame < iVar2)))) {
              cVar3 = events->triggerCount;
              events->triggerCount = cVar3 + '\x01';
              events->triggeredIds[(u8)cVar3] = eventId;
            }
            if (((bVar13 == 3) && (iVar2 < (int)eventFrame)) && ((int)eventFrame <= iVar1)) {
              cVar3 = events->triggerCount;
              events->triggerCount = cVar3 + '\x01';
              events->triggeredIds[(u8)cVar3] = eventId;
            }
            if ((bVar13 == 2) && ((iVar2 < (int)eventFrame || ((int)eventFrame <= iVar1)))) {
              cVar3 = events->triggerCount;
              events->triggerCount = cVar3 + '\x01';
              events->triggeredIds[(u8)cVar3] = eventId;
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
#pragma peephole reset
#pragma scheduling reset

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
undefined4 Object_ObjAnimSetMoveProgress(f32 moveProgress,ObjAnimComponent *objAnim)
{
  if (moveProgress > lbl_803DE908) {
    moveProgress = lbl_803DE908;
  }
  else if (moveProgress < lbl_803DE8F0) {
    moveProgress = lbl_803DE8F0;
  }
  objAnim->activeMoveProgress = moveProgress;
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
#pragma peephole off
undefined4
Object_ObjAnimSetMove(f32 moveProgress,int objAnimArg,int moveId,int flags)
{
  ObjAnimComponent *objAnim;
  ObjAnimBank *bank;
  ObjAnimDef *animDef;
  ObjAnimState *state;
  short previousMove;
  u8 moveChanged;
  int frameStep;
  int moveIndex;
  int moveData;
  float clampedProgress;
  objAnim = (ObjAnimComponent *)objAnimArg;
  clampedProgress = moveProgress;
  if (clampedProgress > lbl_803DE8E0) {
    clampedProgress = lbl_803DE8E0;
  }
  else if (clampedProgress < lbl_803DE8F0) {
    clampedProgress = lbl_803DE8F0;
  }
  objAnim->activeMoveProgress = clampedProgress;
  bank = ObjAnim_GetActiveBank(objAnim);
  animDef = bank->animDef;
  if (animDef->moveCount == 0) {
    return 0;
  }
  state = bank->activeState;
  state->flags = (s8)flags;
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
  previousMove = objAnim->activeMove;
  moveChanged = previousMove != moveId;
  objAnim->activeMove = (s16)moveId;
  moveIndex = ObjAnim_ResolveMoveIndex(animDef,moveId);
  if ((animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) != 0) {
    if (moveChanged != 0) {
      state->blendToggle = '\x01' - state->blendToggle;
      state->moveCacheSlot = (u16)state->blendToggle;
      if (animDef->blendMoveIds[moveIndex] == -1) {
        OSReport(gObjAnimSetBlendMoveMissingAnimWarning,animDef->modNo);
        moveIndex = 0;
      }
      ObjAnim_LoadCachedMove((int)animDef->blendMoveIds[moveIndex],(int)(s16)moveIndex,
                             state->moveCache[state->moveCacheSlot],animDef);
    }
    moveData = (int)state->moveCache[state->moveCacheSlot] + OBJANIM_CACHED_MOVE_DATA_OFFSET;
  }
  else {
    state->moveCacheSlot = (u16)moveIndex;
    moveData = (int)animDef->moveData[state->moveCacheSlot];
  }
  state->frameData = (u8 *)(moveData + OBJANIM_FRAME_CMD_OFFSET);
  state->frameType = *(s8 *)(moveData + 1) & OBJANIM_FRAME_TYPE_MASK;
  state->segmentLength =
       ObjAnim_U32AsDouble((uint)state->frameData[1]) - lbl_803DE8E8;
  if (state->frameType == 0) {
    state->segmentLength = state->segmentLength - lbl_803DE8E0;
  }
  frameStep = *(s8 *)(moveData + 1) & OBJANIM_FRAME_STEP_MASK;
  if (frameStep != 0) {
    state->savedStep = state->step;
    state->eventStep =
         (short)(int)(lbl_803DE8F4 /
                      (float)(ObjAnim_U32AsDouble(frameStep ^ 0x80000000) - lbl_803DE900));
    state->eventCountdown = OBJANIM_EVENT_COUNTDOWN_RESET;
  }
  state->step = lbl_803DE8F0;
  state->speed = clampedProgress * state->segmentLength;
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjAnim_GetCurrentEventCountdown
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
#pragma peephole off
undefined2 ObjAnim_GetCurrentEventCountdown(ObjAnimComponent *objAnim)
{
  return ObjAnim_GetCurrentState(objAnim)->eventCountdown;
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
void ObjAnim_WriteStateWord(ObjAnimComponent *objAnim,int stateIndex,short wordIndex,int value)
{
  ObjAnimBank *bank;
  ObjAnimState *state;
  u16 stateWord;

  bank = ObjAnim_GetActiveBank(objAnim);
  if (bank == (ObjAnimBank *)0x0) {
    return;
  }
  stateWord = value;
  if (stateIndex != 0) {
    state = bank->activeState;
  }
  else {
    state = bank->currentState;
  }
  state = (ObjAnimState *)((u8 *)state + wordIndex * 2);
  state->eventCountdown = stateWord;
}

/*
 * --INFO--
 *
 * Function: ObjAnim_SetCurrentEventStepFrames
 * EN v1.0 Address: 0x8002F574
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x8002F66C
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjAnim_SetCurrentEventStepFrames(ObjAnimComponent *objAnim,uint frameCount)
{
  ObjAnimBank *bank;

  bank = ObjAnim_GetActiveBank(objAnim);
  if (bank != (ObjAnimBank *)0x0) {
    bank->currentState->eventStep =
        (short)(int)(lbl_803DE8F4 /
                    (ObjAnim_U32AsDouble(frameCount ^ 0x80000000) - lbl_803DE900));
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjAnim_SampleRootCurvePhase
 * EN v1.0 Address: 0x8002F5D4
 * EN v1.0 Size: 1140b
 * EN v1.1 Address: 0x8002F6CC
 * EN v1.1 Size: 1140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
undefined4 ObjAnim_SampleRootCurvePhase(double distance,int objAnimArg,float *phaseOut)
{
  ObjAnimComponent *objAnim;
  ObjAnimBank *bank;
  ObjAnimDef *animDef;
  ObjAnimState *state;
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  short sVar6;
  float fVar7;
  float fVar8;
  bool bVar9;
  uint uVar10;
  uint uVar11;
  int *piVar12;
  int iVar13;
  float *pfVar14;
  float *pfVar15;
  float *pfVar16;
  int iVar17;
  int iVar18;
  double in_f6;
  double in_f7;
  double in_f8;
  undefined8 local_20;

  objAnim = (ObjAnimComponent *)objAnimArg;
  bank = ObjAnim_GetActiveBank(objAnim);
  piVar12 = (int *)bank;
  animDef = bank->animDef;
  iVar17 = (int)animDef;
  if (animDef->moveCount != 0) {
    state = bank->currentState;
    iVar18 = (int)state;
    fVar5 = *(float *)(objAnimArg + 8);
    pfVar15 = (float *)0x0;
    if (state->eventState != 0) {
      in_f7 = (double)((float)((double)CONCAT44(0x43300000,(uint)state->eventState) -
                              lbl_803DE8E8) / lbl_803DE8F4);
      in_f8 = (double)(float)((double)lbl_803DE8E0 - in_f7);
      if ((*(ushort *)(iVar17 + 2) & OBJANIM_DEF_FLAG_CACHED_MOVES) == 0) {
        iVar13 = *(int *)(*(int *)(iVar17 + 100) + (uint)*(ushort *)(iVar18 + 0x48) * 4);
      }
      else {
        iVar13 = *(int *)(iVar18 + (uint)*(ushort *)(iVar18 + 0x48) * 4 + 0x24) +
                 OBJANIM_CACHED_MOVE_DATA_OFFSET;
      }
      if (*(short *)(iVar13 + OBJANIM_MOVE_ROOT_CURVE_OFFSET) != 0) {
        pfVar16 = (float *)(iVar13 + *(short *)(iVar13 + OBJANIM_MOVE_ROOT_CURVE_OFFSET));
        in_f6 = (double)(*pfVar16 * fVar5);
        pfVar15 = (float *)((int)pfVar16 + OBJANIM_ROOT_CURVE_AXIS_DATA_OFFSET);
        if (((*(short *)pfVar15 == 0) && (pfVar15 = pfVar16 + 2, *(short *)pfVar15 == 0)) &&
           (pfVar15 = (float *)((int)pfVar16 + OBJANIM_ROOT_CURVE_Z_AXIS_OFFSET),
           *(short *)pfVar15 == 0)) {
          pfVar15 = (float *)0x0;
        }
        if (pfVar15 != (float *)0x0) {
          pfVar15 = (float *)((int)pfVar15 + 2);
        }
      }
    }
    if ((*(ushort *)(iVar17 + 2) & OBJANIM_DEF_FLAG_CACHED_MOVES) == 0) {
      iVar17 = *(int *)(*(int *)(iVar17 + 100) + (uint)*(ushort *)(iVar18 + 0x44) * 4);
    }
    else {
      iVar17 = *(int *)(iVar18 + (uint)*(ushort *)(iVar18 + 0x44) * 4 + 0x1c) +
               OBJANIM_CACHED_MOVE_DATA_OFFSET;
    }
    if (*(short *)(iVar17 + OBJANIM_MOVE_ROOT_CURVE_OFFSET) != 0) {
      pfVar16 = (float *)(iVar17 + *(short *)(iVar17 + OBJANIM_MOVE_ROOT_CURVE_OFFSET));
      fVar7 = *pfVar16 * fVar5;
      uVar10 = (int)*(short *)(pfVar16 + 1) - 1;
      pfVar14 = (float *)((int)pfVar16 + OBJANIM_ROOT_CURVE_AXIS_DATA_OFFSET);
      if ((*(short *)pfVar14 == 0) && (pfVar14 = pfVar16 + 2, *(short *)pfVar14 == 0)) {
        pfVar14 = (float *)((int)pfVar16 + OBJANIM_ROOT_CURVE_Z_AXIS_OFFSET);
      }
      if (*(short *)pfVar14 != 0) {
        sVar6 = *(short *)((int)pfVar14 + uVar10 * 2 + 2);
        if (sVar6 < 0) {
          fVar7 = -fVar7;
        }
        if (sVar6 != 0) {
          fVar4 = (float)((double)CONCAT44(0x43300000,uVar10 ^ 0x80000000) - lbl_803DE900);
          fVar8 = lbl_803DE8E0 / fVar4;
          fVar4 = fVar4 * objAnim->currentMoveProgress;
          uVar11 = (uint)fVar4;
          fVar4 = fVar4 - (float)((double)CONCAT44(0x43300000,uVar11 ^ 0x80000000) - lbl_803DE900
                                 );
          if (pfVar15 == (float *)0x0) {
            fVar1 = fVar7 * (float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)((int)pfVar14 + uVar11 * 2 + 2)
                                                     ^ 0x80000000) - lbl_803DE900);
            fVar2 = fVar7 * (float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)((int)pfVar14 + uVar11 * 2 + 4)
                                                     ^ 0x80000000) - lbl_803DE900);
          }
          else {
            if (*(short *)((int)pfVar15 + uVar10 * 2) < 0) {
              in_f6 = -in_f6;
            }
            iVar17 = uVar11 * 2;
            local_20 = (double)CONCAT44(0x43300000,
                                        (int)*(short *)((int)pfVar15 + iVar17) ^ 0x80000000);
            fVar1 = (float)(in_f6 * (double)(float)(in_f7 * (double)(float)(local_20 -
                                                                           lbl_803DE900)) +
                           (double)(fVar7 * (float)(in_f8 * (double)(float)((double)CONCAT44(
                                                  0x43300000,
                                                  (int)*(short *)((int)pfVar14 + iVar17 + 2) ^
                                                  0x80000000) - lbl_803DE900))));
            fVar2 = (float)(in_f6 * (double)(float)(in_f7 * (double)(float)((double)CONCAT44(
                                                  0x43300000,
                                                  (int)*(short *)((int)pfVar15 + iVar17 + 2) ^
                                                  0x80000000) - lbl_803DE900)) +
                           (double)(fVar7 * (float)(in_f8 * (double)(float)((double)CONCAT44(
                                                  0x43300000,
                                                  (int)*(short *)((int)pfVar14 + iVar17 + 4) ^
                                                  0x80000000) - lbl_803DE900))));
          }
          fVar5 = (float)(distance * (double)(fVar5 / *(float *)(*(int *)(objAnimArg + 0x50) + 4))) +
                  fVar4 * (fVar2 - fVar1) + fVar1;
          fVar4 = -(fVar8 * fVar4 - fVar8);
          bVar9 = false;
          do {
            if (fVar2 <= fVar5) {
              uVar11 = uVar11 + 1;
              if ((int)uVar10 <= (int)uVar11) {
                uVar11 = 0;
              }
              if (pfVar15 == (float *)0x0) {
                fVar3 = fVar7 * ((float)((double)CONCAT44(0x43300000,
                                                          (int)*(short *)((int)pfVar14 +
                                                                         uVar11 * 2 + 4) ^
                                                          0x80000000) - lbl_803DE900) -
                                (float)((double)CONCAT44(0x43300000,
                                                         (int)*(short *)((int)pfVar14 +
                                                                        uVar11 * 2 + 2) ^ 0x80000000
                                                        ) - lbl_803DE900));
              }
              else {
                iVar17 = uVar11 * 2;
                local_20 = (double)CONCAT44(0x43300000,
                                            (int)((short *)((int)pfVar15 + iVar17))[1] ^ 0x80000000)
                ;
                fVar3 = (float)((double)(fVar7 * ((float)((double)CONCAT44(0x43300000,
                                                                           (int)*(short *)((int)
                                                  pfVar14 + iVar17 + 4) ^ 0x80000000) -
                                                  lbl_803DE900) -
                                                 (float)((double)CONCAT44(0x43300000,
                                                                          (int)*(short *)((int)
                                                  pfVar14 + iVar17 + 2) ^ 0x80000000) -
                                                  lbl_803DE900))) * in_f8 +
                               (double)(float)((double)(float)(in_f6 * (double)((float)(local_20 -
                                                  lbl_803DE900) -
                                                  (float)((double)CONCAT44(0x43300000,
                                                                           (int)*(short *)((int)
                                                  pfVar15 + iVar17) ^ 0x80000000) - lbl_803DE900)
                                                  )) * in_f7));
              }
              fVar4 = fVar4 + fVar8;
              fVar1 = fVar2;
              fVar2 = fVar2 + fVar3;
            }
            else {
              fVar4 = fVar4 - (fVar8 * (fVar2 - fVar5)) / (fVar2 - fVar1);
              bVar9 = true;
            }
          } while (!bVar9);
          if (phaseOut != (float *)0x0) {
            *phaseOut = fVar4;
          }
          return 1;
        }
        return 0;
      }
    }
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjAnim_AdvanceCurrentMove
 * EN v1.0 Address: 0x8002FA48
 * EN v1.0 Size: 2236b
 * EN v1.1 Address: 0x8002FB40
 * EN v1.1 Size: 2236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
undefined4 ObjAnim_AdvanceCurrentMove(double moveStepScale,double deltaTime,int objAnimArg,
                                      ObjAnimEventList *events)
{
  ObjAnimComponent *objAnim;
  ObjAnimBank *bank;
  ObjAnimDef *animDef;
  ObjAnimState *state;
  double dVar1;
  char cVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  uint uVar15;
  uint uVar16;
  undefined uVar17;
  undefined4 uVar18;
  int iVar21;
  int *piVar22;
  int iVar23;
  int iVar24;
  int iVar25;
  int iVar26;
  float *pfVar27;
  short *psVar28;
  byte bVar29;
  int iVar30;
  double dVar31;
  undefined8 local_48;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_20;
  float *pfVar20;

  pfVar20 = (float *)events;
  dVar31 = (double)lbl_803DE90C;
  uVar18 = 0;
  if ((dVar31 <= moveStepScale) &&
     (dVar31 = moveStepScale, (double)lbl_803DE8E0 < moveStepScale)) {
    dVar31 = (double)lbl_803DE8E0;
  }
  objAnim = (ObjAnimComponent *)objAnimArg;
  bank = ObjAnim_GetActiveBank(objAnim);
  piVar22 = (int *)bank;
  animDef = bank->animDef;
  if ((animDef->moveCount != 0) &&
     (state = bank->currentState, iVar24 = (int)state, iVar24 != 0)) {
    state->step = (float)(dVar31 * (double)state->segmentLength);
    if (state->eventCountdown != 0) {
      if ((state->flags & 8) != 0) {
        state->savedStep = state->step;
      }
      state->progress =
           (float)((double)state->savedStep * deltaTime + (double)state->progress);
      fVar4 = lbl_803DE8F0;
      fVar3 = state->prevSegmentLength;
      if (state->prevFrameType == '\0') {
        fVar4 = state->progress;
        fVar5 = lbl_803DE8F0;
        if ((lbl_803DE8F0 <= fVar4) && (fVar5 = fVar4, fVar3 < fVar4)) {
          fVar5 = fVar3;
        }
        state->progress = fVar5;
      }
      else {
        if (state->progress < lbl_803DE8F0) {
          while (state->progress < fVar4) {
            state->progress = state->progress + fVar3;
          }
        }
        if (fVar3 <= state->progress) {
          while (fVar3 <= state->progress) {
            state->progress = state->progress - fVar3;
          }
        }
      }
      if ((state->flags & 2) == 0) {
        uVar15 = (uint)-(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 (uint)state->eventStep) -
                                               lbl_803DE8E8) * deltaTime -
                               (double)(float)((double)CONCAT44(0x43300000,
                                                                state->eventCountdown ^
                                                                0x80000000) - lbl_803DE900));
        fVar3 = lbl_803DE8F0;
        if ((-1 < (int)uVar15) &&
           (uVar15 = uVar15 ^ 0x80000000, fVar3 = lbl_803DE8F4,
           (float)((double)CONCAT44(0x43300000,uVar15) - lbl_803DE900) <= lbl_803DE8F4)) {
          local_38 = (double)CONCAT44(0x43300000,uVar15);
          fVar3 = (float)(local_38 - lbl_803DE900);
        }
        state->eventCountdown = (short)(int)fVar3;
      }
      if (state->eventCountdown == 0) {
        state->prevEventState = 0;
      }
    }
    fVar4 = objAnim->currentMoveProgress;
    fVar3 = (float)(dVar31 * deltaTime);
    objAnim->currentMoveProgress = fVar4 + fVar3;
    fVar6 = lbl_803DE8F0;
    fVar5 = lbl_803DE8E0;
    if (objAnim->currentMoveProgress < lbl_803DE8E0) {
      if (objAnim->currentMoveProgress < lbl_803DE8F0) {
        if (state->frameType == '\0') {
          objAnim->currentMoveProgress = lbl_803DE8F0;
        }
        else {
          while (objAnim->currentMoveProgress < fVar6) {
            objAnim->currentMoveProgress = objAnim->currentMoveProgress + fVar5;
          }
        }
        uVar18 = 1;
      }
    }
    else if (state->frameType == '\0') {
      objAnim->currentMoveProgress = lbl_803DE8E0;
      uVar18 = 1;
    }
    else {
      while (fVar5 <= objAnim->currentMoveProgress) {
        objAnim->currentMoveProgress = objAnim->currentMoveProgress - fVar5;
      }
      uVar18 = 1;
    }
    if (pfVar20 != (float *)0x0) {
      *(undefined *)((int)pfVar20 + 0x12) = 0;
      fVar5 = lbl_803DE8F0;
      pfVar20[2] = lbl_803DE8F0;
      pfVar20[1] = fVar5;
      *pfVar20 = fVar5;
      if (*(int *)(objAnimArg + 0x60) != 0) {
        *(undefined *)((int)pfVar20 + 0x1b) = 0;
        iVar23 = **(int **)(objAnimArg + 0x60) >> 1;
        if (iVar23 != 0) {
          iVar30 = (int)(lbl_803DE8F8 * fVar4);
          iVar26 = (int)(lbl_803DE8F8 * objAnim->currentMoveProgress);
          bVar29 = iVar26 < iVar30;
          if (fVar3 < lbl_803DE8F0) {
            bVar29 = bVar29 | 2;
          }
          iVar25 = 0;
          iVar21 = 0;
          while ((iVar25 < iVar23 &&
                  (*(char *)((int)pfVar20 + 0x1b) < OBJANIM_EVENT_TRIGGER_CAPACITY))) {
            uVar16 = (uint)*(short *)(*(int *)(*(int *)(objAnimArg + 0x60) + 4) + iVar21);
            uVar15 = uVar16 & OBJANIM_EVENT_FRAME_MASK;
            uVar16 = uVar16 >> OBJANIM_EVENT_ID_SHIFT & OBJANIM_EVENT_ID_MASK;
            if (uVar16 != OBJANIM_EVENT_ID_NONE) {
              uVar17 = (undefined)uVar16;
              if (((bVar29 == 0) && (iVar30 <= (int)uVar15)) && ((int)uVar15 < iVar26)) {
                cVar2 = *(char *)((int)pfVar20 + 0x1b);
                *(char *)((int)pfVar20 + 0x1b) = cVar2 + '\x01';
                *(undefined *)((int)pfVar20 + cVar2 + 0x13) = uVar17;
              }
              if ((bVar29 == 1) && ((iVar30 <= (int)uVar15 || ((int)uVar15 < iVar26)))) {
                cVar2 = *(char *)((int)pfVar20 + 0x1b);
                *(char *)((int)pfVar20 + 0x1b) = cVar2 + '\x01';
                *(undefined *)((int)pfVar20 + cVar2 + 0x13) = uVar17;
              }
              if (((bVar29 == 3) && (iVar26 < (int)uVar15)) && ((int)uVar15 <= iVar30)) {
                cVar2 = *(char *)((int)pfVar20 + 0x1b);
                *(char *)((int)pfVar20 + 0x1b) = cVar2 + '\x01';
                *(undefined *)((int)pfVar20 + cVar2 + 0x13) = uVar17;
              }
              if ((bVar29 == 2) && ((iVar26 < (int)uVar15 || ((int)uVar15 <= iVar30)))) {
                cVar2 = *(char *)((int)pfVar20 + 0x1b);
                *(char *)((int)pfVar20 + 0x1b) = cVar2 + '\x01';
                *(undefined *)((int)pfVar20 + cVar2 + 0x13) = uVar17;
              }
            }
            iVar21 = iVar21 + 2;
            iVar25 = iVar25 + 1;
          }
        }
      }
      if ((*(ushort *)(*piVar22 + 2) & OBJANIM_DEF_FLAG_CACHED_MOVES) == 0) {
        iVar23 = *(int *)(*(int *)(*piVar22 + 100) + (uint)*(ushort *)(iVar24 + 0x44) * 4);
      }
      else {
        iVar23 = *(int *)(iVar24 + (uint)*(ushort *)(iVar24 + 0x44) * 4 + 0x1c) + 0x80;
      }
      if (*(short *)(iVar23 + OBJANIM_MOVE_ROOT_CURVE_OFFSET) == 0) {
        *(undefined *)((int)pfVar20 + 0x12) = 0;
      }
      else {
        *(undefined *)((int)pfVar20 + 0x12) = 1;
        pfVar27 = (float *)(iVar23 + *(short *)(iVar23 + OBJANIM_MOVE_ROOT_CURVE_OFFSET));
        fVar5 = *pfVar27;
        fVar6 = *(float *)(objAnimArg + 8);
        iVar23 = (int)*(short *)(pfVar27 + 1);
        psVar28 = (short *)((int)pfVar27 + OBJANIM_ROOT_CURVE_AXIS_DATA_OFFSET);
        local_30 = (double)CONCAT44(0x43300000,iVar23 - 1U ^ 0x80000000);
        fVar7 = (float)(local_30 - lbl_803DE900) * fVar4;
        uVar15 = (uint)fVar7;
        dVar31 = (double)CONCAT44(0x43300000,uVar15 ^ 0x80000000) - lbl_803DE900;
        fVar8 = (float)(local_30 - lbl_803DE900) * objAnim->currentMoveProgress;
        uVar16 = (uint)fVar8;
        dVar1 = (double)CONCAT44(0x43300000,uVar16 ^ 0x80000000) - lbl_803DE900;
        iVar30 = 0;
        fVar11 = lbl_803DE8F0;
        fVar13 = lbl_803DE8E0;
        if (*(ushort *)(iVar24 + 0x5a) != 0) {
          local_30 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar24 + 0x5a));
          fVar11 = (float)(local_30 - lbl_803DE8E8) / lbl_803DE8F4;
          if ((*(ushort *)(*piVar22 + 2) & OBJANIM_DEF_FLAG_CACHED_MOVES) == 0) {
            iVar24 = *(int *)(*(int *)(*piVar22 + 100) + (uint)*(ushort *)(iVar24 + 0x48) * 4);
          }
          else {
            iVar24 = *(int *)(iVar24 + (uint)*(ushort *)(iVar24 + 0x48) * 4 + 0x24) + 0x80;
          }
          iVar30 = iVar24 + *(short *)(iVar24 + OBJANIM_MOVE_ROOT_CURVE_OFFSET) +
                   OBJANIM_ROOT_CURVE_AXIS_DATA_OFFSET;
          fVar13 = lbl_803DE8E0 - fVar11;
        }
        iVar26 = 0;
        iVar24 = (iVar23 - 1U) * 2;
        pfVar27 = pfVar20;
        do {
          if (*psVar28 == 0) {
            psVar28 = psVar28 + 1;
            if (iVar30 != 0) {
              iVar30 = iVar30 + 2;
            }
            if (iVar26 < OBJANIM_ROOT_CURVE_TRANSLATION_AXIS_COUNT) {
              *pfVar20 = lbl_803DE8F0;
            }
            else {
              *(undefined2 *)((int)pfVar27 + 6) = 0;
            }
          }
          else {
            if (iVar30 != 0) {
              iVar30 = iVar30 + 2;
            }
            local_30 = (double)CONCAT44(0x43300000,(int)psVar28[uVar15 + 1] ^ 0x80000000);
            fVar9 = fVar13 * (float)(local_30 - lbl_803DE900);
            if (iVar30 != 0) {
              local_38 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(uVar15 * 2 + iVar30) ^ 0x80000000);
              fVar9 = fVar11 * (float)(local_38 - lbl_803DE900) + fVar9;
            }
            fVar10 = fVar13 * (float)((double)CONCAT44(0x43300000,
                                                       (int)(psVar28 + uVar15 + 1)[1] ^ 0x80000000)
                                     - lbl_803DE900);
            if (iVar30 != 0) {
              local_48 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(uVar15 * 2 + iVar30 + 2) ^ 0x80000000);
              fVar10 = fVar11 * (float)(local_48 - lbl_803DE900) + fVar10;
            }
            fVar12 = fVar13 * (float)((double)CONCAT44(0x43300000,
                                                       (int)psVar28[uVar16 + 1] ^ 0x80000000) -
                                     lbl_803DE900);
            if (iVar30 != 0) {
              fVar12 = fVar11 * (float)((double)CONCAT44(0x43300000,
                                                         (int)*(short *)(uVar16 * 2 + iVar30) ^
                                                         0x80000000) - lbl_803DE900) + fVar12;
            }
            fVar14 = fVar13 * (float)((double)CONCAT44(0x43300000,
                                                       (int)(psVar28 + uVar16 + 1)[1] ^ 0x80000000)
                                     - lbl_803DE900);
            if (iVar30 != 0) {
              local_20 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(uVar16 * 2 + iVar30 + 2) ^ 0x80000000);
              fVar14 = fVar11 * (float)(local_20 - lbl_803DE900) + fVar14;
            }
            fVar12 = (fVar8 - (float)dVar1) * (fVar14 - fVar12) + fVar12;
            if (fVar3 <= lbl_803DE8F0) {
              if (fVar4 < objAnim->currentMoveProgress) {
                local_20 = (double)CONCAT44(0x43300000,(int)psVar28[iVar23] ^ 0x80000000);
                fVar12 = -(fVar13 * (float)(local_20 - lbl_803DE900) - fVar12);
                if (iVar30 != 0) {
                  local_20 = (double)CONCAT44(0x43300000,
                                              (int)*(short *)(iVar24 + iVar30) ^ 0x80000000);
                  fVar12 = fVar11 * (float)(local_20 - lbl_803DE900) + fVar12;
                }
              }
            }
            else if (objAnim->currentMoveProgress < fVar4) {
              local_20 = (double)CONCAT44(0x43300000,(int)psVar28[iVar23] ^ 0x80000000);
              fVar12 = fVar13 * (float)(local_20 - lbl_803DE900) + fVar12;
              if (iVar30 != 0) {
                local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar24 + iVar30) ^ 0x80000000
                                           );
                fVar12 = fVar11 * (float)(local_20 - lbl_803DE900) + fVar12;
              }
            }
            fVar12 = fVar12 - ((fVar7 - (float)dVar31) * (fVar10 - fVar9) + fVar9);
            if (iVar26 < OBJANIM_ROOT_CURVE_TRANSLATION_AXIS_COUNT) {
              *pfVar20 = fVar12 * fVar5 * fVar6;
            }
            else {
              *(short *)((int)pfVar27 + 6) = (short)(int)fVar12;
            }
            psVar28 = psVar28 + iVar23 + 1;
            if (iVar30 != 0) {
              iVar30 = iVar30 + iVar23 * 2;
            }
          }
          pfVar20 = pfVar20 + 1;
          pfVar27 = (float *)((int)pfVar27 + 2);
          iVar26 = iVar26 + 1;
        } while (iVar26 < OBJANIM_ROOT_CURVE_AXIS_COUNT);
      }
    }
  }
  return uVar18;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjAnim_SetMoveProgress
 * EN v1.0 Address: 0x80030304
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x800303FC
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 ObjAnim_SetMoveProgress(f32 moveProgress,ObjAnimComponent *objAnim)
{
  if (moveProgress > lbl_803DE908) {
    moveProgress = lbl_803DE908;
  }
  else if (moveProgress < lbl_803DE8F0) {
    moveProgress = lbl_803DE8F0;
  }
  objAnim->currentMoveProgress = moveProgress;
  return 0;
}

/*
 * --INFO--
 *
 * Function: ObjAnim_SetCurrentMove
 * EN v1.0 Address: 0x80030334
 * EN v1.0 Size: 852b
 * EN v1.1 Address: 0x8003042C
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 ObjAnim_SetCurrentMove(double moveProgress,int objAnimArg,int moveId,u32 flags)
{
  ObjAnimComponent *objAnim;
  ObjAnimBank *bank;
  ObjAnimDef *animDef;
  ObjAnimState *state;
  s16 previousMove;
  u8 moveChanged;
  int frameStep;
  int moveIndex;
  int moveData;
  f32 clampedProgress;
  ObjHitReactState *hitState;

  objAnim = (ObjAnimComponent *)objAnimArg;
  clampedProgress = (float)moveProgress;
  if (lbl_803DE8E0 < clampedProgress) {
    clampedProgress = lbl_803DE8E0;
  }
  else if (clampedProgress < lbl_803DE8F0) {
    clampedProgress = lbl_803DE8F0;
  }
  objAnim->currentMoveProgress = clampedProgress;
  bank = ObjAnim_GetActiveBank(objAnim);
  if (bank == (ObjAnimBank *)0x0) {
    return 0;
  }
  animDef = bank->animDef;
  if (animDef->moveCount == 0) {
    return 0;
  }
  state = bank->currentState;
  state->flags = (s8)flags;
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
  hitState = objAnim->hitReactState;
  if ((hitState != (ObjHitReactState *)0x0) && (hitState->entries != (ObjHitReactEntry *)0x0)) {
    ObjHitReact_LoadMoveEntries(objAnimArg,bank,(int)objAnim->objType,hitState,moveId,0);
  }
  if (objAnim->eventTable != (ObjAnimEventTable *)0x0) {
    ObjAnim_LoadMoveEvents(objAnimArg,(int)objAnim->objType,objAnim->eventTable,moveId,0);
  }
  previousMove = objAnim->currentMove;
  moveChanged = previousMove != moveId;
  objAnim->currentMove = (s16)moveId;
  moveIndex = ObjAnim_ResolveMoveIndex(animDef,moveId);
  if ((animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) != 0) {
    if (moveChanged != 0) {
      state->blendToggle = '\x01' - state->blendToggle;
      state->moveCacheSlot = (u16)state->blendToggle;
      if (animDef->blendMoveIds[moveIndex] == -1) {
        OSReport(gObjAnimSetBlendMoveMissingAnimWarning,animDef->modNo);
        moveIndex = 0;
      }
      ObjAnim_LoadCachedMove((int)animDef->blendMoveIds[moveIndex],(int)(s16)moveIndex,
                             state->moveCache[state->moveCacheSlot],animDef);
    }
    moveData = (int)state->moveCache[state->moveCacheSlot] + OBJANIM_CACHED_MOVE_DATA_OFFSET;
  }
  else {
    state->moveCacheSlot = (u16)moveIndex;
    moveData = (int)animDef->moveData[state->moveCacheSlot];
  }
  state->frameData = (u8 *)(moveData + OBJANIM_FRAME_CMD_OFFSET);
  state->frameType = *(s8 *)(moveData + 1) & OBJANIM_FRAME_TYPE_MASK;
  state->segmentLength =
       ObjAnim_U32AsDouble((uint)state->frameData[1]) - lbl_803DE8E8;
  if (state->frameType == 0) {
    state->segmentLength = state->segmentLength - lbl_803DE8E0;
  }
  frameStep = *(s8 *)(moveData + 1) & OBJANIM_FRAME_STEP_MASK;
  if ((frameStep != 0) && ((flags & 0x10) == 0)) {
    state->savedStep = state->step;
    state->eventStep =
         (short)(int)(lbl_803DE8F4 /
                      (float)(ObjAnim_U32AsDouble(frameStep ^ 0x80000000) - lbl_803DE900));
    state->eventCountdown = OBJANIM_EVENT_COUNTDOWN_RESET;
  }
  else {
    state->eventCountdown = 0;
  }
  state->step = lbl_803DE8F0;
  state->speed = clampedProgress * state->segmentLength;
  return 0;
}
