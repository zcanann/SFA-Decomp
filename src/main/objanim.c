#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/objHitReact.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"

extern undefined4 FUN_800723a0();
extern void ObjAnim_LoadCachedMove(int animId,int moveIndex,u8 *cache,ObjAnimDef *animDef);
extern void ObjAnim_LoadMoveEvents(int objAnim,int objType,ObjAnimEventTable *eventTable,u32 moveId,
                                   int async);

extern char gObjAnimSetBlendMoveMissingAnimWarning[];
extern f64 gObjAnimU32ToDoubleBias;
extern f64 gObjAnimS32ToDoubleBias;
extern f32 gObjAnimProgressOne;
extern f32 gObjAnimProgressZero;
extern f32 gObjAnimEventStepScale;
extern f32 gObjAnimEventFrameScale;
extern f32 lbl_803DE908;
extern f32 lbl_803DE90C;

/*
 * --INFO--
 *
 * Function: ObjAnim_SetBlendMove
 * EN v1.0 Address: 0x8002EB54
 * EN v1.0 Size: 452b
 * EN v1.1 Address: 0x8002EC4C
 * EN v1.1 Size: 452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 *
 * Retail string evidence labels this source-side path as objanim.c/setBlendMove.
 */
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void ObjAnim_SetBlendMove(ObjAnimComponent *objAnim,ObjAnimDef *animDef,ObjAnimState *state,
                          uint moveId,s16 eventState)
{
  int moveIndex;
  ObjAnimMoveData *moveData;
  int frameType;
  float frameValue;

  moveIndex = (int)animDef->moveGroupBaseIndices[(int)moveId >> OBJANIM_MOVE_GROUP_SHIFT] +
              (moveId & OBJANIM_MOVE_INDEX_MASK);
  if (moveIndex >= (int)animDef->moveCount) {
    moveIndex = animDef->moveCount - 1;
  }
  if (moveIndex < 0) {
    moveIndex = 0;
  }
  if ((animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) != 0) {
    if (state->lastBlendMoveIndex != moveIndex) {
      state->blendCacheSlot = (u16)state->blendToggle;
      state->prevBlendCacheSlot = (u16)(OBJANIM_MOVE_CACHE_SLOT_COUNT - 1 - state->blendToggle);
      if (animDef->cachedAnimIds[moveIndex] == OBJANIM_MISSING_MOVE_ID) {
        OSReport(gObjAnimSetBlendMoveMissingAnimWarning,animDef->modNo);
        moveIndex = 0;
      }
      ObjAnim_LoadCachedMove((int)animDef->cachedAnimIds[moveIndex],(int)(s16)moveIndex,
                             state->blendMoveCache[state->blendCacheSlot],animDef);
      state->lastBlendMoveIndex = (s16)moveIndex;
    }
    moveData =
        (ObjAnimMoveData *)(state->blendMoveCache[state->blendCacheSlot] +
                            OBJANIM_CACHED_MOVE_DATA_OFFSET);
  }
  else {
    state->blendCacheSlot = (u16)moveIndex;
    moveData = (ObjAnimMoveData *)animDef->moveData[state->blendCacheSlot];
  }
  state->frameCmd = moveData->frameCmd;
  frameType = moveData->frameInfo & OBJANIM_FRAME_TYPE_MASK;
  if (frameType != state->frameType) {
    state->eventState = 0;
  }
  else {
    frameValue = (float)state->frameCmd[1];
    if (frameType == OBJANIM_FRAME_TYPE_CLAMPED) {
      frameValue = frameValue - gObjAnimProgressOne;
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
 * EN v1.0 Address: 0x8002ED18
 * EN v1.0 Size: 84b
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
    ObjAnim_SetBlendMove(objAnim,bank->animDef,bank->activeState,moveId,(s16)eventState);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: Object_ObjAnimSetSecondaryBlendMove
 * EN v1.0 Address: 0x8002ED6C
 * EN v1.0 Size: 84b
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
    ObjAnim_SetBlendMove(objAnim,bank->animDef,bank->currentState,moveId,(s16)eventState);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: Object_ObjAnimAdvanceMove
 * EN v1.0 Address: 0x8002EDC0
 * EN v1.0 Size: 1100b
 * EN v1.1 Address: 0x8002EEB8
 * EN v1.1 Size: 1100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int Object_ObjAnimAdvanceMove(f32 moveStepScale,f32 deltaTime,int objAnimArg,ObjAnimEventList *events)
{
  ObjAnimComponent *objAnim;
  ObjAnimEventTable *eventTable;
  ObjAnimBank *bank;
  ObjAnimState *state;
  int previousEventFrame;
  int currentEventFrame;
  char triggerSlot;
  float fVar4;
  float fVar5;
  float fVar6;
  int moveWrappedOrEnded;
  int eventByteOffset;
  int eventCountdown;
  int *piVar10;
  int iVar11;
  int eventIndex;
  byte eventScanFlags;
  s16 eventWord;
  u8 eventId;
  u16 eventFrame;
  double local_28;

  objAnim = (ObjAnimComponent *)objAnimArg;
  moveWrappedOrEnded = 0;
  bank = ObjAnim_GetActiveBank(objAnim);
  piVar10 = (int *)bank;
  if (bank->animDef->moveCount == 0) {
    moveWrappedOrEnded = 0;
  }
  else {
    state = bank->activeState;
    iVar11 = (int)state;
    state->step = moveStepScale * state->segmentLength;
    if (state->eventCountdown != 0) {
      if ((state->flags & OBJANIM_STATE_FLAG_REFRESH_SAVED_STEP) != 0) {
        state->savedStep = state->step;
      }
      state->progress = state->savedStep * deltaTime + state->progress;
      fVar5 = gObjAnimProgressZero;
      fVar4 = state->prevSegmentLength;
      if (state->prevFrameType != OBJANIM_FRAME_TYPE_CLAMPED) {
        if (state->progress < gObjAnimProgressZero) {
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
      else {
        fVar5 = state->progress;
        fVar6 = gObjAnimProgressZero;
        if ((gObjAnimProgressZero <= fVar5) && (fVar6 = fVar5, fVar4 < fVar5)) {
          fVar6 = fVar4;
        }
        state->progress = fVar6;
      }
      if ((state->flags & OBJANIM_STATE_FLAG_HOLD_EVENT_COUNTDOWN) == 0) {
        eventCountdown =
            (int)-(float)((ObjAnim_U32AsDouble((uint)state->eventStep) -
                           gObjAnimU32ToDoubleBias) *
                              deltaTime -
                          (ObjAnim_U32AsDouble(state->eventCountdown ^ OBJANIM_S32_DOUBLE_BIAS_XOR) -
                           gObjAnimS32ToDoubleBias));
        fVar4 = gObjAnimProgressZero;
        if ((-1 < eventCountdown) &&
           (eventCountdown = eventCountdown ^ OBJANIM_S32_DOUBLE_BIAS_XOR, fVar4 = gObjAnimEventStepScale,
           ObjAnim_U32AsDouble(eventCountdown) - gObjAnimS32ToDoubleBias <= gObjAnimEventStepScale)) {
          local_28 = ObjAnim_U32AsDouble(eventCountdown);
          fVar4 = local_28 - gObjAnimS32ToDoubleBias;
        }
        state->eventCountdown = (u16)(int)fVar4;
      }
      if (state->eventCountdown == 0) {
        state->prevEventState = 0;
      }
    }
    fVar4 = objAnim->activeMoveProgress;
    objAnim->activeMoveProgress = fVar4 + moveStepScale * deltaTime;
    fVar6 = gObjAnimProgressZero;
    fVar5 = gObjAnimProgressOne;
    if (objAnim->activeMoveProgress >= gObjAnimProgressOne) {
      if (state->frameType == OBJANIM_FRAME_TYPE_CLAMPED) {
        objAnim->activeMoveProgress = gObjAnimProgressOne;
      }
      else {
        while (fVar5 <= objAnim->activeMoveProgress) {
          objAnim->activeMoveProgress = objAnim->activeMoveProgress - fVar5;
        }
      }
      moveWrappedOrEnded = 1;
    }
    else if (objAnim->activeMoveProgress < gObjAnimProgressZero) {
      if (state->frameType == OBJANIM_FRAME_TYPE_CLAMPED) {
        objAnim->activeMoveProgress = gObjAnimProgressZero;
      }
      else {
        while (objAnim->activeMoveProgress < fVar6) {
          objAnim->activeMoveProgress = objAnim->activeMoveProgress + fVar5;
        }
      }
      moveWrappedOrEnded = 1;
    }
    if ((events != (ObjAnimEventList *)0) &&
        (events->rootCurveValid = 0, objAnim->eventTable != 0)) {
      eventTable = objAnim->eventTable;
      events->triggerCount = 0;
      iVar11 = eventTable->byteCount >> 1;
      if (iVar11 != 0) {
        previousEventFrame = (int)(gObjAnimEventFrameScale * fVar4);
        currentEventFrame = (int)(gObjAnimEventFrameScale * objAnim->activeMoveProgress);
        eventScanFlags = currentEventFrame < previousEventFrame;
        if (moveStepScale * deltaTime < gObjAnimProgressZero) {
          eventScanFlags = eventScanFlags | 2;
        }
        eventIndex = 0;
        eventByteOffset = 0;
        while ((eventIndex < iVar11 && (events->triggerCount < OBJANIM_EVENT_TRIGGER_CAPACITY))) {
          eventWord = *(s16 *)((u8 *)eventTable->entries + eventByteOffset);
          eventFrame = eventWord & OBJANIM_EVENT_FRAME_MASK;
          eventId = eventWord >> OBJANIM_EVENT_ID_SHIFT & OBJANIM_EVENT_ID_MASK;
          if (eventId != OBJANIM_EVENT_ID_NONE) {
            if (((eventScanFlags == OBJANIM_EVENT_SCAN_FORWARD) &&
                (previousEventFrame <= (int)eventFrame)) &&
               ((int)eventFrame < currentEventFrame)) {
              triggerSlot = events->triggerCount;
              events->triggerCount = triggerSlot + '\x01';
              events->triggeredIds[(u8)triggerSlot] = eventId;
            }
            if ((eventScanFlags == OBJANIM_EVENT_SCAN_WRAPPED) &&
               ((previousEventFrame <= (int)eventFrame ||
                ((int)eventFrame < currentEventFrame)))) {
              triggerSlot = events->triggerCount;
              events->triggerCount = triggerSlot + '\x01';
              events->triggeredIds[(u8)triggerSlot] = eventId;
            }
            if (((eventScanFlags == OBJANIM_EVENT_SCAN_REVERSE_WRAPPED) &&
                (currentEventFrame < (int)eventFrame)) &&
               ((int)eventFrame <= previousEventFrame)) {
              triggerSlot = events->triggerCount;
              events->triggerCount = triggerSlot + '\x01';
              events->triggeredIds[(u8)triggerSlot] = eventId;
            }
            if ((eventScanFlags == OBJANIM_EVENT_SCAN_REVERSE) &&
               ((currentEventFrame < (int)eventFrame ||
                ((int)eventFrame <= previousEventFrame)))) {
              triggerSlot = events->triggerCount;
              events->triggerCount = triggerSlot + '\x01';
              events->triggeredIds[(u8)triggerSlot] = eventId;
            }
          }
          eventByteOffset = eventByteOffset + 2;
          eventIndex = eventIndex + 1;
        }
      }
    }
  }
  return moveWrappedOrEnded;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: Object_ObjAnimSetMoveProgress
 * EN v1.0 Address: 0x8002F20C
 * EN v1.0 Size: 48b
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
  else if (moveProgress < gObjAnimProgressZero) {
    moveProgress = gObjAnimProgressZero;
  }
  objAnim->activeMoveProgress = moveProgress;
  return 0;
}

/*
 * --INFO--
 *
 * Function: Object_ObjAnimSetMove
 * EN v1.0 Address: 0x8002F23C
 * EN v1.0 Size: 720b
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
  ObjAnimMoveData *moveData;
  float eventStepFrames;
  objAnim = (ObjAnimComponent *)objAnimArg;
  if (moveProgress > gObjAnimProgressOne) {
    moveProgress = gObjAnimProgressOne;
  }
  else if (moveProgress < gObjAnimProgressZero) {
    moveProgress = gObjAnimProgressZero;
  }
  objAnim->activeMoveProgress = moveProgress;
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
  state->lastBlendMoveIndex = OBJANIM_BLEND_MOVE_INDEX_INVALID;
  previousMove = objAnim->activeMove;
  moveChanged = previousMove != moveId;
  objAnim->activeMove = (s16)moveId;
  moveId = (int)animDef->moveGroupBaseIndices[moveId >> OBJANIM_MOVE_GROUP_SHIFT] +
           (moveId & OBJANIM_MOVE_INDEX_MASK);
  if (moveId >= (int)animDef->moveCount) {
    moveId = animDef->moveCount - 1;
  }
  if (moveId < 0) {
    moveId = 0;
  }
  if ((animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) != 0) {
    if (moveChanged != 0) {
      state->blendToggle = OBJANIM_MOVE_CACHE_SLOT_COUNT - 1 - state->blendToggle;
      state->moveCacheSlot = (u16)state->blendToggle;
      if (animDef->cachedAnimIds[moveId] == OBJANIM_MISSING_MOVE_ID) {
        OSReport(gObjAnimSetBlendMoveMissingAnimWarning,animDef->modNo);
        moveId = 0;
      }
      ObjAnim_LoadCachedMove((int)animDef->cachedAnimIds[moveId],(int)(s16)moveId,
                             state->moveCache[state->moveCacheSlot],animDef);
    }
    moveData =
        (ObjAnimMoveData *)(state->moveCache[state->moveCacheSlot] +
                            OBJANIM_CACHED_MOVE_DATA_OFFSET);
  }
  else {
    state->moveCacheSlot = (u16)moveId;
    moveData = (ObjAnimMoveData *)animDef->moveData[state->moveCacheSlot];
  }
  state->frameData = moveData->frameCmd;
  state->frameType = moveData->frameInfo & OBJANIM_FRAME_TYPE_MASK;
  state->segmentLength = (float)state->frameData[1];
  if (state->frameType == OBJANIM_FRAME_TYPE_CLAMPED) {
    state->segmentLength = state->segmentLength - gObjAnimProgressOne;
  }
  frameStep = moveData->frameInfo & OBJANIM_FRAME_STEP_MASK;
  if (frameStep != 0) {
    state->savedStep = state->step;
    eventStepFrames = gObjAnimEventStepScale / (float)frameStep;
    state->eventStep = eventStepFrames;
    state->eventCountdown = OBJANIM_EVENT_COUNTDOWN_RESET;
  }
  state->step = gObjAnimProgressZero;
  state->speed = moveProgress * state->segmentLength;
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
  float eventStepFrames;

  bank = ObjAnim_GetActiveBank(objAnim);
  if (bank != (ObjAnimBank *)0x0) {
    eventStepFrames = gObjAnimEventStepScale / (float)(s32)frameCount;
    bank->currentState->eventStep = eventStepFrames;
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
undefined4 ObjAnim_SampleRootCurvePhase(f32 distance,ObjAnimComponent *objAnim,float *phaseOut)
{
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
  int uVar10;
  int uVar11;
  int *piVar12;
  int iVar13;
  float *pfVar14;
  float *pfVar15;
  float *pfVar16;
  int iVar17;
  int iVar18;
  float in_f6;
  float in_f7;
  float in_f8;
  undefined8 local_20;

  bank = ObjAnim_GetActiveBank(objAnim);
  piVar12 = (int *)bank;
  animDef = bank->animDef;
  iVar17 = (int)animDef;
  if (animDef->moveCount != 0) {
    state = bank->currentState;
    iVar18 = (int)state;
    fVar5 = objAnim->rootMotionScale;
    pfVar15 = (float *)0x0;
    if (state->eventState != 0) {
      in_f7 = (float)(ObjAnim_U32AsDouble((uint)state->eventState) - gObjAnimU32ToDoubleBias) /
              gObjAnimEventStepScale;
      in_f8 = gObjAnimProgressOne - in_f7;
      if ((*(ushort *)(iVar17 + 2) & OBJANIM_DEF_FLAG_CACHED_MOVES) == 0) {
        iVar13 = *(int *)(*(int *)(iVar17 + 100) + (uint)*(ushort *)(iVar18 + 0x48) * 4);
      }
      else {
        iVar13 = *(int *)(iVar18 + (uint)*(ushort *)(iVar18 + 0x48) * 4 + 0x24) +
                 OBJANIM_CACHED_MOVE_DATA_OFFSET;
      }
      if (*(short *)(iVar13 + OBJANIM_MOVE_ROOT_CURVE_OFFSET) != 0) {
        pfVar16 = (float *)(iVar13 + *(short *)(iVar13 + OBJANIM_MOVE_ROOT_CURVE_OFFSET));
        in_f6 = *pfVar16 * fVar5;
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
          fVar4 = (float)(ObjAnim_S32AsDouble((s32)uVar10) - gObjAnimS32ToDoubleBias);
          fVar8 = gObjAnimProgressOne / fVar4;
          fVar4 = fVar4 * objAnim->currentMoveProgress;
          uVar11 = (int)fVar4;
          fVar4 = fVar4 - (float)(ObjAnim_S32AsDouble((s32)uVar11) -
                                  gObjAnimS32ToDoubleBias);
          if (pfVar15 == (float *)0x0) {
            fVar1 = fVar7 *
                    (float)(ObjAnim_S32AsDouble(*(s16 *)((int)pfVar14 + uVar11 * 2 + 2)) -
                            gObjAnimS32ToDoubleBias);
            fVar2 = fVar7 *
                    (float)(ObjAnim_S32AsDouble(*(s16 *)((int)pfVar14 + uVar11 * 2 + 4)) -
                            gObjAnimS32ToDoubleBias);
          }
          else {
            if (*(short *)((int)pfVar15 + uVar10 * 2) < 0) {
              in_f6 = -in_f6;
            }
            iVar17 = uVar11 * 2;
            local_20 = ObjAnim_S32AsDouble(*(s16 *)((int)pfVar15 + iVar17));
            fVar1 = in_f6 * (in_f7 * (float)(local_20 - gObjAnimS32ToDoubleBias)) +
                    fVar7 *
                        (in_f8 *
                         (float)(ObjAnim_S32AsDouble(*(s16 *)((int)pfVar14 + iVar17 + 2)) -
                                 gObjAnimS32ToDoubleBias));
            fVar2 = in_f6 *
                        (in_f7 *
                         (float)(ObjAnim_S32AsDouble(*(s16 *)((int)pfVar15 + iVar17 + 2)) -
                                 gObjAnimS32ToDoubleBias)) +
                    fVar7 *
                        (in_f8 *
                         (float)(ObjAnim_S32AsDouble(*(s16 *)((int)pfVar14 + iVar17 + 4)) -
                                 gObjAnimS32ToDoubleBias));
          }
          fVar5 = distance * (fVar5 / *(float *)((int)objAnim->modelInstance + 4)) +
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
                fVar3 = fVar7 *
                        ((float)(ObjAnim_S32AsDouble(*(s16 *)((int)pfVar14 + uVar11 * 2 + 4)) -
                                 gObjAnimS32ToDoubleBias) -
                         (float)(ObjAnim_S32AsDouble(*(s16 *)((int)pfVar14 + uVar11 * 2 + 2)) -
                                 gObjAnimS32ToDoubleBias));
              }
              else {
                iVar17 = uVar11 * 2;
                local_20 = ObjAnim_S32AsDouble(((s16 *)((int)pfVar15 + iVar17))[1]);
                fVar3 = fVar7 *
                            ((float)(ObjAnim_S32AsDouble(*(s16 *)((int)pfVar14 + iVar17 + 4)) -
                                     gObjAnimS32ToDoubleBias) -
                             (float)(ObjAnim_S32AsDouble(*(s16 *)((int)pfVar14 + iVar17 + 2)) -
                                     gObjAnimS32ToDoubleBias)) *
                            in_f8 +
                        in_f6 *
                            ((float)(local_20 - gObjAnimS32ToDoubleBias) -
                             (float)(ObjAnim_S32AsDouble(*(s16 *)((int)pfVar15 + iVar17)) -
                                     gObjAnimS32ToDoubleBias)) *
                            in_f7;
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
undefined4 ObjAnim_AdvanceCurrentMove(f32 moveStepScale,f32 deltaTime,int objAnimArg,
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
     (dVar31 = moveStepScale, (double)gObjAnimProgressOne < moveStepScale)) {
    dVar31 = (double)gObjAnimProgressOne;
  }
  objAnim = (ObjAnimComponent *)objAnimArg;
  bank = ObjAnim_GetActiveBank(objAnim);
  piVar22 = (int *)bank;
  animDef = bank->animDef;
  if ((animDef->moveCount != 0) &&
     (state = bank->currentState, iVar24 = (int)state, iVar24 != 0)) {
    state->step = (float)(dVar31 * (double)state->segmentLength);
    if (state->eventCountdown != 0) {
      if ((state->flags & OBJANIM_STATE_FLAG_REFRESH_SAVED_STEP) != 0) {
        state->savedStep = state->step;
      }
      state->progress =
           (float)((double)state->savedStep * deltaTime + (double)state->progress);
      fVar4 = gObjAnimProgressZero;
      fVar3 = state->prevSegmentLength;
      if (state->prevFrameType != OBJANIM_FRAME_TYPE_CLAMPED) {
        if (state->progress < gObjAnimProgressZero) {
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
      else {
        fVar4 = state->progress;
        fVar5 = gObjAnimProgressZero;
        if ((gObjAnimProgressZero <= fVar4) && (fVar5 = fVar4, fVar3 < fVar4)) {
          fVar5 = fVar3;
        }
        state->progress = fVar5;
      }
      if ((state->flags & OBJANIM_STATE_FLAG_HOLD_EVENT_COUNTDOWN) == 0) {
        uVar15 = (uint)-(float)((double)(float)((double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,
                                                                 (uint)state->eventStep) -
                                               gObjAnimU32ToDoubleBias) * deltaTime -
                               (double)(float)((double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,
                                                                state->eventCountdown ^
                                                                OBJANIM_S32_DOUBLE_BIAS_XOR) - gObjAnimS32ToDoubleBias));
        fVar3 = gObjAnimProgressZero;
        if ((-1 < (int)uVar15) &&
           (uVar15 = uVar15 ^ OBJANIM_S32_DOUBLE_BIAS_XOR, fVar3 = gObjAnimEventStepScale,
           (float)((double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,uVar15) - gObjAnimS32ToDoubleBias) <= gObjAnimEventStepScale)) {
          local_38 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,uVar15);
          fVar3 = (float)(local_38 - gObjAnimS32ToDoubleBias);
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
    fVar6 = gObjAnimProgressZero;
    fVar5 = gObjAnimProgressOne;
    if (objAnim->currentMoveProgress >= gObjAnimProgressOne) {
      if (state->frameType == OBJANIM_FRAME_TYPE_CLAMPED) {
        objAnim->currentMoveProgress = gObjAnimProgressOne;
      }
      else {
        while (fVar5 <= objAnim->currentMoveProgress) {
          objAnim->currentMoveProgress = objAnim->currentMoveProgress - fVar5;
        }
      }
      uVar18 = 1;
    }
    else if (objAnim->currentMoveProgress < gObjAnimProgressZero) {
      if (state->frameType == OBJANIM_FRAME_TYPE_CLAMPED) {
        objAnim->currentMoveProgress = gObjAnimProgressZero;
      }
      else {
        while (objAnim->currentMoveProgress < fVar6) {
          objAnim->currentMoveProgress = objAnim->currentMoveProgress + fVar5;
        }
      }
      uVar18 = 1;
    }
    if (pfVar20 != (float *)0x0) {
      *(undefined *)((int)pfVar20 + 0x12) = 0;
      fVar5 = gObjAnimProgressZero;
      pfVar20[2] = gObjAnimProgressZero;
      pfVar20[1] = fVar5;
      *pfVar20 = fVar5;
      if (*(int *)(objAnimArg + 0x60) != 0) {
        *(undefined *)((int)pfVar20 + 0x1b) = 0;
        iVar23 = **(int **)(objAnimArg + 0x60) >> 1;
        if (iVar23 != 0) {
          iVar30 = (int)(gObjAnimEventFrameScale * fVar4);
          iVar26 = (int)(gObjAnimEventFrameScale * objAnim->currentMoveProgress);
          bVar29 = iVar26 < iVar30;
          if (fVar3 < gObjAnimProgressZero) {
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
              if (((bVar29 == OBJANIM_EVENT_SCAN_FORWARD) && (iVar30 <= (int)uVar15)) &&
                  ((int)uVar15 < iVar26)) {
                cVar2 = *(char *)((int)pfVar20 + 0x1b);
                *(char *)((int)pfVar20 + 0x1b) = cVar2 + '\x01';
                *(undefined *)((int)pfVar20 + cVar2 + 0x13) = uVar17;
              }
              if ((bVar29 == OBJANIM_EVENT_SCAN_WRAPPED) &&
                  ((iVar30 <= (int)uVar15 || ((int)uVar15 < iVar26)))) {
                cVar2 = *(char *)((int)pfVar20 + 0x1b);
                *(char *)((int)pfVar20 + 0x1b) = cVar2 + '\x01';
                *(undefined *)((int)pfVar20 + cVar2 + 0x13) = uVar17;
              }
              if (((bVar29 == OBJANIM_EVENT_SCAN_REVERSE_WRAPPED) &&
                  (iVar26 < (int)uVar15)) && ((int)uVar15 <= iVar30)) {
                cVar2 = *(char *)((int)pfVar20 + 0x1b);
                *(char *)((int)pfVar20 + 0x1b) = cVar2 + '\x01';
                *(undefined *)((int)pfVar20 + cVar2 + 0x13) = uVar17;
              }
              if ((bVar29 == OBJANIM_EVENT_SCAN_REVERSE) &&
                  ((iVar26 < (int)uVar15 || ((int)uVar15 <= iVar30)))) {
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
        fVar6 = objAnim->rootMotionScale;
        iVar23 = (int)*(short *)(pfVar27 + 1);
        psVar28 = (short *)((int)pfVar27 + OBJANIM_ROOT_CURVE_AXIS_DATA_OFFSET);
        local_30 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,iVar23 - 1U ^ OBJANIM_S32_DOUBLE_BIAS_XOR);
        fVar7 = (float)(local_30 - gObjAnimS32ToDoubleBias) * fVar4;
        uVar15 = (uint)fVar7;
        dVar31 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,uVar15 ^ OBJANIM_S32_DOUBLE_BIAS_XOR) - gObjAnimS32ToDoubleBias;
        fVar8 = (float)(local_30 - gObjAnimS32ToDoubleBias) * objAnim->currentMoveProgress;
        uVar16 = (uint)fVar8;
        dVar1 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,uVar16 ^ OBJANIM_S32_DOUBLE_BIAS_XOR) - gObjAnimS32ToDoubleBias;
        iVar30 = 0;
        fVar11 = gObjAnimProgressZero;
        fVar13 = gObjAnimProgressOne;
        if (*(ushort *)(iVar24 + 0x5a) != 0) {
          local_30 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,(uint)*(ushort *)(iVar24 + 0x5a));
          fVar11 = (float)(local_30 - gObjAnimU32ToDoubleBias) / gObjAnimEventStepScale;
          if ((*(ushort *)(*piVar22 + 2) & OBJANIM_DEF_FLAG_CACHED_MOVES) == 0) {
            iVar24 = *(int *)(*(int *)(*piVar22 + 100) + (uint)*(ushort *)(iVar24 + 0x48) * 4);
          }
          else {
            iVar24 = *(int *)(iVar24 + (uint)*(ushort *)(iVar24 + 0x48) * 4 + 0x24) + 0x80;
          }
          iVar30 = iVar24 + *(short *)(iVar24 + OBJANIM_MOVE_ROOT_CURVE_OFFSET) +
                   OBJANIM_ROOT_CURVE_AXIS_DATA_OFFSET;
          fVar13 = gObjAnimProgressOne - fVar11;
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
              *pfVar20 = gObjAnimProgressZero;
            }
            else {
              *(undefined2 *)((int)pfVar27 + 6) = 0;
            }
          }
          else {
            if (iVar30 != 0) {
              iVar30 = iVar30 + 2;
            }
            local_30 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,(int)psVar28[uVar15 + 1] ^ OBJANIM_S32_DOUBLE_BIAS_XOR);
            fVar9 = fVar13 * (float)(local_30 - gObjAnimS32ToDoubleBias);
            if (iVar30 != 0) {
              local_38 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,
                                          (int)*(short *)(uVar15 * 2 + iVar30) ^ OBJANIM_S32_DOUBLE_BIAS_XOR);
              fVar9 = fVar11 * (float)(local_38 - gObjAnimS32ToDoubleBias) + fVar9;
            }
            fVar10 = fVar13 * (float)((double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,
                                                       (int)(psVar28 + uVar15 + 1)[1] ^ OBJANIM_S32_DOUBLE_BIAS_XOR)
                                     - gObjAnimS32ToDoubleBias);
            if (iVar30 != 0) {
              local_48 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,
                                          (int)*(short *)(uVar15 * 2 + iVar30 + 2) ^ OBJANIM_S32_DOUBLE_BIAS_XOR);
              fVar10 = fVar11 * (float)(local_48 - gObjAnimS32ToDoubleBias) + fVar10;
            }
            fVar12 = fVar13 * (float)((double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,
                                                       (int)psVar28[uVar16 + 1] ^ OBJANIM_S32_DOUBLE_BIAS_XOR) -
                                     gObjAnimS32ToDoubleBias);
            if (iVar30 != 0) {
              fVar12 = fVar11 * (float)((double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,
                                                         (int)*(short *)(uVar16 * 2 + iVar30) ^
                                                         OBJANIM_S32_DOUBLE_BIAS_XOR) - gObjAnimS32ToDoubleBias) + fVar12;
            }
            fVar14 = fVar13 * (float)((double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,
                                                       (int)(psVar28 + uVar16 + 1)[1] ^ OBJANIM_S32_DOUBLE_BIAS_XOR)
                                     - gObjAnimS32ToDoubleBias);
            if (iVar30 != 0) {
              local_20 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,
                                          (int)*(short *)(uVar16 * 2 + iVar30 + 2) ^ OBJANIM_S32_DOUBLE_BIAS_XOR);
              fVar14 = fVar11 * (float)(local_20 - gObjAnimS32ToDoubleBias) + fVar14;
            }
            fVar12 = (fVar8 - (float)dVar1) * (fVar14 - fVar12) + fVar12;
            if (fVar3 <= gObjAnimProgressZero) {
              if (fVar4 < objAnim->currentMoveProgress) {
                local_20 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,(int)psVar28[iVar23] ^ OBJANIM_S32_DOUBLE_BIAS_XOR);
                fVar12 = -(fVar13 * (float)(local_20 - gObjAnimS32ToDoubleBias) - fVar12);
                if (iVar30 != 0) {
                  local_20 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,
                                              (int)*(short *)(iVar24 + iVar30) ^ OBJANIM_S32_DOUBLE_BIAS_XOR);
                  fVar12 = fVar11 * (float)(local_20 - gObjAnimS32ToDoubleBias) + fVar12;
                }
              }
            }
            else if (objAnim->currentMoveProgress < fVar4) {
              local_20 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,(int)psVar28[iVar23] ^ OBJANIM_S32_DOUBLE_BIAS_XOR);
              fVar12 = fVar13 * (float)(local_20 - gObjAnimS32ToDoubleBias) + fVar12;
              if (iVar30 != 0) {
                local_20 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,(int)*(short *)(iVar24 + iVar30) ^ OBJANIM_S32_DOUBLE_BIAS_XOR
                                           );
                fVar12 = fVar11 * (float)(local_20 - gObjAnimS32ToDoubleBias) + fVar12;
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
  else if (moveProgress < gObjAnimProgressZero) {
    moveProgress = gObjAnimProgressZero;
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
#pragma scheduling off
#pragma peephole off
undefined4 ObjAnim_SetCurrentMove(f32 moveProgress,int objAnimArg,int moveId,int flags)
{
  ObjAnimComponent *objAnim;
  ObjAnimBank *bank;
  ObjAnimDef *animDef;
  ObjAnimState *state;
  s16 previousMove;
  u8 moveChanged;
  int frameStep;
  ObjAnimMoveData *moveData;
  float eventStepFrames;
  ObjHitReactState *hitState;

  objAnim = (ObjAnimComponent *)objAnimArg;
  if (moveProgress > gObjAnimProgressOne) {
    moveProgress = gObjAnimProgressOne;
  }
  else if (moveProgress < gObjAnimProgressZero) {
    moveProgress = gObjAnimProgressZero;
  }
  objAnim->currentMoveProgress = moveProgress;
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
  state->lastBlendMoveIndex = OBJANIM_BLEND_MOVE_INDEX_INVALID;
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
  moveId = (int)animDef->moveGroupBaseIndices[moveId >> OBJANIM_MOVE_GROUP_SHIFT] +
           (moveId & OBJANIM_MOVE_INDEX_MASK);
  if (moveId >= (int)animDef->moveCount) {
    moveId = animDef->moveCount - 1;
  }
  if (moveId < 0) {
    moveId = 0;
  }
  if ((animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) != 0) {
    if (moveChanged != 0) {
      state->blendToggle = OBJANIM_MOVE_CACHE_SLOT_COUNT - 1 - state->blendToggle;
      state->moveCacheSlot = (u16)state->blendToggle;
      if (animDef->cachedAnimIds[moveId] == OBJANIM_MISSING_MOVE_ID) {
        OSReport(gObjAnimSetBlendMoveMissingAnimWarning,animDef->modNo);
        moveId = 0;
      }
      ObjAnim_LoadCachedMove((int)animDef->cachedAnimIds[moveId],(int)(s16)moveId,
                             state->moveCache[state->moveCacheSlot],animDef);
    }
    moveData =
        (ObjAnimMoveData *)(state->moveCache[state->moveCacheSlot] +
                            OBJANIM_CACHED_MOVE_DATA_OFFSET);
  }
  else {
    state->moveCacheSlot = (u16)moveId;
    moveData = (ObjAnimMoveData *)animDef->moveData[state->moveCacheSlot];
  }
  state->frameData = moveData->frameCmd;
  state->frameType = moveData->frameInfo & OBJANIM_FRAME_TYPE_MASK;
  state->segmentLength = (float)state->frameData[1];
  if (state->frameType == OBJANIM_FRAME_TYPE_CLAMPED) {
    state->segmentLength = state->segmentLength - gObjAnimProgressOne;
  }
  frameStep = moveData->frameInfo & OBJANIM_FRAME_STEP_MASK;
  if ((frameStep != 0) && (((u8)flags & OBJANIM_SET_MOVE_FLAG_SKIP_EVENT_COUNTDOWN) == 0)) {
    state->savedStep = state->step;
    eventStepFrames = gObjAnimEventStepScale / (float)frameStep;
    state->eventStep = eventStepFrames;
    state->eventCountdown = OBJANIM_EVENT_COUNTDOWN_RESET;
  }
  else {
    state->eventCountdown = 0;
  }
  state->step = gObjAnimProgressZero;
  state->speed = moveProgress * state->segmentLength;
  return 0;
}
#pragma peephole reset
#pragma scheduling reset
