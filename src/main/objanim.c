#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/objHitReact.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"

extern undefined4 FUN_800723a0();
extern void ObjAnim_LoadCachedMove(int animId,int moveIndex,u8 *cache,ObjAnimDef *animDef);
extern void ObjAnim_LoadMoveEvents(int objAnim,int objType,ObjAnimEventTable *eventTable,u32 moveId,
                                   int async);
extern void _savegpr_27(void);
extern void _restgpr_27(void);

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

  moveIndex =
      animDef->moveGroupBaseIndices[(s32)moveId >> OBJANIM_MOVE_GROUP_SHIFT] +
      (moveId & OBJANIM_MOVE_INDEX_MASK);
  if (moveIndex >= animDef->moveCount) {
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
      state->eventState = (u16)eventState;
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
int Object_ObjAnimAdvanceMove(f32 moveStepScale,f32 deltaTime,int objAnimArg,
                              ObjAnimEventList *events)
{
  ObjAnimComponent *objAnim;
  ObjAnimBank *bank;
  ObjAnimState *state;
  ObjAnimEventTable *eventTable;
  f32 previousProgress;
  f32 progressDelta;
  f32 value;
  int wrapped;
  int countdown;
  int previousFrame;
  int currentFrame;
  int scanMode;
  int eventCount;
  int eventIndex;
  s16 eventEntry;
  int eventFrame;
  int eventId;
  int shouldEmit;

  objAnim = (ObjAnimComponent *)objAnimArg;
  bank = ObjAnim_GetActiveBank(objAnim);
  if (bank->animDef->moveCount == 0) {
    return 0;
  }

  wrapped = 0;
  state = bank->activeState;
  state->step = moveStepScale * state->segmentLength;
  if (state->eventCountdown != 0) {
    if ((state->flags & OBJANIM_STATE_FLAG_REFRESH_SAVED_STEP) != 0) {
      state->savedStep = state->step;
    }
    state->progress += state->savedStep * deltaTime;
    if (state->prevFrameType != OBJANIM_FRAME_TYPE_CLAMPED) {
      while (state->progress < gObjAnimProgressZero) {
        state->progress += state->prevSegmentLength;
      }
      while (state->progress >= state->prevSegmentLength) {
        state->progress -= state->prevSegmentLength;
      }
    }
    else if (state->progress < gObjAnimProgressZero) {
      state->progress = gObjAnimProgressZero;
    }
    else if (state->progress > state->prevSegmentLength) {
      state->progress = state->prevSegmentLength;
    }

    if ((state->flags & OBJANIM_STATE_FLAG_HOLD_EVENT_COUNTDOWN) == 0) {
      countdown =
          (int)((f32)state->eventCountdown - ((f32)state->eventStep * deltaTime));
      if (countdown < 0) {
        value = gObjAnimProgressZero;
      }
      else if ((f32)countdown > gObjAnimEventStepScale) {
        value = gObjAnimEventStepScale;
      }
      else {
        value = (f32)countdown;
      }
      state->eventCountdown = (u16)(int)value;
    }
    if (state->eventCountdown == 0) {
      state->prevEventState = 0;
    }
  }

  previousProgress = objAnim->activeMoveProgress;
  progressDelta = moveStepScale * deltaTime;
  objAnim->activeMoveProgress = previousProgress + progressDelta;
  if (objAnim->activeMoveProgress >= gObjAnimProgressOne) {
    if (state->frameType != OBJANIM_FRAME_TYPE_CLAMPED) {
      while (objAnim->activeMoveProgress >= gObjAnimProgressOne) {
        objAnim->activeMoveProgress -= gObjAnimProgressOne;
      }
    }
    else {
      objAnim->activeMoveProgress = gObjAnimProgressOne;
    }
    wrapped = 1;
  }
  else if (objAnim->activeMoveProgress < gObjAnimProgressZero) {
    if (state->frameType != OBJANIM_FRAME_TYPE_CLAMPED) {
      while (objAnim->activeMoveProgress < gObjAnimProgressZero) {
        objAnim->activeMoveProgress += gObjAnimProgressOne;
      }
    }
    else {
      objAnim->activeMoveProgress = gObjAnimProgressZero;
    }
    wrapped = 1;
  }

  if (events == NULL) {
    return wrapped;
  }

  events->rootCurveValid = 0;
  eventTable = objAnim->eventTable;
  if (eventTable == NULL) {
    return wrapped;
  }

  events->triggerCount = 0;
  eventCount = eventTable->byteCount >> 1;
  if (eventCount == 0) {
    return wrapped;
  }

  previousFrame = (int)(gObjAnimEventFrameScale * previousProgress);
  currentFrame = (int)(gObjAnimEventFrameScale * objAnim->activeMoveProgress);
  scanMode = OBJANIM_EVENT_SCAN_FORWARD;
  if (currentFrame < previousFrame) {
    scanMode |= OBJANIM_EVENT_SCAN_WRAPPED;
  }
  if (progressDelta < gObjAnimProgressZero) {
    scanMode |= OBJANIM_EVENT_SCAN_REVERSE;
  }

  for (eventIndex = 0;
       eventIndex < eventCount && events->triggerCount < OBJANIM_EVENT_TRIGGER_CAPACITY;
       eventIndex++) {
    eventEntry = eventTable->entries[eventIndex];
    eventFrame = eventEntry & OBJANIM_EVENT_FRAME_MASK;
    eventId = (eventEntry >> OBJANIM_EVENT_ID_SHIFT) & OBJANIM_EVENT_ID_MASK;
    if (eventId == OBJANIM_EVENT_ID_NONE) {
      continue;
    }

    shouldEmit = 0;
    if (scanMode == OBJANIM_EVENT_SCAN_FORWARD) {
      shouldEmit = (previousFrame <= eventFrame) && (eventFrame < currentFrame);
    }
    else if (scanMode == OBJANIM_EVENT_SCAN_WRAPPED) {
      shouldEmit = (eventFrame >= previousFrame) || (eventFrame < currentFrame);
    }
    else if (scanMode == OBJANIM_EVENT_SCAN_REVERSE_WRAPPED) {
      shouldEmit = (eventFrame > currentFrame) && (eventFrame <= previousFrame);
    }
    else if (scanMode == OBJANIM_EVENT_SCAN_REVERSE) {
      shouldEmit = (eventFrame > currentFrame) || (eventFrame <= previousFrame);
    }

    if (shouldEmit != 0) {
      events->triggeredIds[events->triggerCount] = (s8)eventId;
      events->triggerCount++;
    }
  }

  return wrapped;
}

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
int Object_ObjAnimSetMoveProgress(f32 moveProgress,ObjAnimComponent *objAnim)
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
int
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
  moveId = ObjAnim_ResolveMoveIndex(animDef,moveId);
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
u16 ObjAnim_GetCurrentEventCountdown(ObjAnimComponent *objAnim)
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
asm int ObjAnim_SampleRootCurvePhase(f32 distance,ObjAnimComponent *objAnim,float *phaseOut)
{
  nofralloc
  stwu r1, -0x30(r1)
  lwz r5, 0x7c(r3)
  lbz r0, 0xad(r3)
  extsb r0, r0
  slwi r0, r0, 2
  lwzx r5, r5, r0
  lwz r7, 0x0(r5)
  lhz r0, 0xec(r7)
  cmplwi r0, 0x0
  bne ObjAnim_SampleRootCurvePhase_L_8002F604
  li r3, 0x0
  b ObjAnim_SampleRootCurvePhase_L_8002FA40
ObjAnim_SampleRootCurvePhase_L_8002F604:
  lwz r8, 0x2c(r5)
  lfs f3, 0x8(r3)
  lwz r5, 0x50(r3)
  lfs f0, 0x4(r5)
  fdivs f0, f3, f0
  fmuls f2, f1, f0
  li r6, 0x0
  lhz r0, 0x5a(r8)
  cmplwi r0, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002F6E4
  lfd f1, gObjAnimU32ToDoubleBias
  stw r0, 0xc(r1)
  lis r0, 0x4330
  stw r0, 0x8(r1)
  lfd f0, 0x8(r1)
  fsubs f1, f0, f1
  lfs f0, gObjAnimEventStepScale
  fdivs f7, f1, f0
  lfs f0, gObjAnimProgressOne
  fsubs f8, f0, f7
  lhz r0, 0x2(r7)
  rlwinm r0, r0, 0, 25, 25
  cmpwi r0, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002F67C
  lhz r0, 0x48(r8)
  slwi r0, r0, 2
  add r5, r8, r0
  lwz r5, 0x24(r5)
  addi r5, r5, 0x80
  b ObjAnim_SampleRootCurvePhase_L_8002F68C
ObjAnim_SampleRootCurvePhase_L_8002F67C:
  lwz r5, 0x64(r7)
  lhz r0, 0x48(r8)
  slwi r0, r0, 2
  lwzx r5, r5, r0
ObjAnim_SampleRootCurvePhase_L_8002F68C:
  lha r0, 0x4(r5)
  cmpwi r0, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002F6E4
  add r6, r5, r0
  lfs f0, 0x0(r6)
  fmuls f6, f0, f3
  addi r6, r6, 0x6
  lha r0, 0x0(r6)
  cmpwi r0, 0x0
  bne ObjAnim_SampleRootCurvePhase_L_8002F6D8
  addi r6, r6, 0x2
  lha r0, 0x0(r6)
  cmpwi r0, 0x0
  bne ObjAnim_SampleRootCurvePhase_L_8002F6D8
  addi r6, r6, 0x2
  lha r0, 0x0(r6)
  cmpwi r0, 0x0
  bne ObjAnim_SampleRootCurvePhase_L_8002F6D8
  li r6, 0x0
ObjAnim_SampleRootCurvePhase_L_8002F6D8:
  cmplwi r6, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002F6E4
  addi r6, r6, 0x2
ObjAnim_SampleRootCurvePhase_L_8002F6E4:
  lhz r0, 0x2(r7)
  rlwinm r0, r0, 0, 25, 25
  cmpwi r0, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002F70C
  lhz r0, 0x44(r8)
  slwi r0, r0, 2
  add r5, r8, r0
  lwz r5, 0x1c(r5)
  addi r5, r5, 0x80
  b ObjAnim_SampleRootCurvePhase_L_8002F71C
ObjAnim_SampleRootCurvePhase_L_8002F70C:
  lwz r5, 0x64(r7)
  lhz r0, 0x44(r8)
  slwi r0, r0, 2
  lwzx r5, r5, r0
ObjAnim_SampleRootCurvePhase_L_8002F71C:
  lha r0, 0x4(r5)
  cmpwi r0, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002FA3C
  add r5, r5, r0
  lfs f0, 0x0(r5)
  fmuls f5, f0, f3
  lha r7, 0x4(r5)
  subi r0, r7, 0x1
  addi r5, r5, 0x6
  li r8, 0x0
  lha r7, 0x0(r5)
  cmpwi r7, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002F754
  li r8, 0x1
ObjAnim_SampleRootCurvePhase_L_8002F754:
  cmpwi r7, 0x0
  bne ObjAnim_SampleRootCurvePhase_L_8002F760
  addi r5, r5, 0x2
ObjAnim_SampleRootCurvePhase_L_8002F760:
  cmpwi r8, 0x0
  bne ObjAnim_SampleRootCurvePhase_L_8002F778
  lha r7, 0x0(r5)
  cmpwi r7, 0x0
  bne ObjAnim_SampleRootCurvePhase_L_8002F778
  addi r5, r5, 0x2
ObjAnim_SampleRootCurvePhase_L_8002F778:
  lha r7, 0x0(r5)
  cmpwi r7, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002FA3C
  slwi r8, r0, 1
  add r7, r5, r8
  lha r7, 0x2(r7)
  cmpwi r7, 0x0
  bge ObjAnim_SampleRootCurvePhase_L_8002F79C
  fneg f5, f5
ObjAnim_SampleRootCurvePhase_L_8002F79C:
  cmpwi r7, 0x0
  bne ObjAnim_SampleRootCurvePhase_L_8002F7AC
  li r3, 0x0
  b ObjAnim_SampleRootCurvePhase_L_8002FA40
ObjAnim_SampleRootCurvePhase_L_8002F7AC:
  lfd f3, gObjAnimS32ToDoubleBias
  xoris r7, r0, 0x8000
  stw r7, 0xc(r1)
  lis r9, 0x4330
  stw r9, 0x8(r1)
  lfd f0, 0x8(r1)
  fsubs f1, f0, f3
  lfs f0, gObjAnimProgressOne
  fdivs f4, f0, f1
  lfs f0, 0x98(r3)
  fmuls f1, f1, f0
  fctiwz f0, f1
  stfd f0, 0x10(r1)
  lwz r3, 0x14(r1)
  xoris r7, r3, 0x8000
  stw r7, 0x1c(r1)
  stw r9, 0x18(r1)
  lfd f0, 0x18(r1)
  fsubs f0, f0, f3
  fsubs f10, f1, f0
  cmplwi r6, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002F8AC
  lhax r7, r6, r8
  cmpwi r7, 0x0
  bge ObjAnim_SampleRootCurvePhase_L_8002F814
  fneg f6, f6
ObjAnim_SampleRootCurvePhase_L_8002F814:
  slwi r10, r3, 1
  add r9, r5, r10
  lha r7, 0x2(r9)
  lfd f9, gObjAnimS32ToDoubleBias
  xoris r7, r7, 0x8000
  stw r7, 0x1c(r1)
  lis r8, 0x4330
  stw r8, 0x18(r1)
  lfd f0, 0x18(r1)
  fsubs f0, f0, f9
  fmuls f0, f8, f0
  fmuls f0, f5, f0
  lhax r7, r6, r10
  xoris r7, r7, 0x8000
  stw r7, 0x14(r1)
  stw r8, 0x10(r1)
  lfd f1, 0x10(r1)
  fsubs f1, f1, f9
  fmuls f1, f7, f1
  fmadds f0, f6, f1, f0
  lha r7, 0x4(r9)
  xoris r7, r7, 0x8000
  stw r7, 0xc(r1)
  stw r8, 0x8(r1)
  lfd f1, 0x8(r1)
  fsubs f1, f1, f9
  fmuls f1, f8, f1
  fmuls f1, f5, f1
  add r7, r6, r10
  lha r7, 0x2(r7)
  xoris r7, r7, 0x8000
  stw r7, 0x24(r1)
  stw r8, 0x20(r1)
  lfd f3, 0x20(r1)
  fsubs f3, f3, f9
  fmuls f3, f7, f3
  fmadds f1, f6, f3, f1
  b ObjAnim_SampleRootCurvePhase_L_8002F8EC
ObjAnim_SampleRootCurvePhase_L_8002F8AC:
  slwi r7, r3, 1
  add r8, r5, r7
  lha r7, 0x2(r8)
  xoris r7, r7, 0x8000
  stw r7, 0x24(r1)
  stw r9, 0x20(r1)
  lfd f0, 0x20(r1)
  fsubs f0, f0, f3
  fmuls f0, f5, f0
  lha r7, 0x4(r8)
  xoris r7, r7, 0x8000
  stw r7, 0x1c(r1)
  stw r9, 0x18(r1)
  lfd f1, 0x18(r1)
  fsubs f1, f1, f3
  fmuls f1, f5, f1
ObjAnim_SampleRootCurvePhase_L_8002F8EC:
  fsubs f3, f1, f0
  fmadds f3, f10, f3, f0
  fadds f2, f2, f3
  fnmsubs f3, f4, f10, f4
  li r11, 0x0
ObjAnim_SampleRootCurvePhase_L_8002F900:
  fcmpo cr0, f1, f2
  ble ObjAnim_SampleRootCurvePhase_L_8002F924
  fsubs f9, f1, f2
  fmuls f10, f4, f9
  fsubs f9, f1, f0
  fdivs f9, f10, f9
  fsubs f3, f3, f9
  li r11, 0x1
  b ObjAnim_SampleRootCurvePhase_L_8002FA20
ObjAnim_SampleRootCurvePhase_L_8002F924:
  addi r3, r3, 0x1
  cmpw r3, r0
  blt ObjAnim_SampleRootCurvePhase_L_8002F934
  li r3, 0x0
ObjAnim_SampleRootCurvePhase_L_8002F934:
  fmr f0, f1
  cmplwi r6, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002F9D4
  slwi r9, r3, 1
  add r10, r5, r9
  lha r7, 0x4(r10)
  lfd f12, gObjAnimS32ToDoubleBias
  xoris r7, r7, 0x8000
  stw r7, 0x24(r1)
  lis r8, 0x4330
  stw r8, 0x20(r1)
  lfd f9, 0x20(r1)
  fsubs f10, f9, f12
  lha r7, 0x2(r10)
  xoris r7, r7, 0x8000
  stw r7, 0x1c(r1)
  stw r8, 0x18(r1)
  lfd f9, 0x18(r1)
  fsubs f9, f9, f12
  fsubs f9, f10, f9
  fmuls f11, f5, f9
  add r9, r6, r9
  lha r7, 0x2(r9)
  xoris r7, r7, 0x8000
  stw r7, 0x14(r1)
  stw r8, 0x10(r1)
  lfd f9, 0x10(r1)
  fsubs f10, f9, f12
  lha r7, 0x0(r9)
  xoris r7, r7, 0x8000
  stw r7, 0xc(r1)
  stw r8, 0x8(r1)
  lfd f9, 0x8(r1)
  fsubs f9, f9, f12
  fsubs f9, f10, f9
  fmuls f9, f6, f9
  fmuls f9, f9, f7
  fmadds f9, f11, f8, f9
  fadds f1, f1, f9
  b ObjAnim_SampleRootCurvePhase_L_8002FA1C
ObjAnim_SampleRootCurvePhase_L_8002F9D4:
  slwi r7, r3, 1
  add r9, r5, r7
  lha r7, 0x4(r9)
  lfd f11, gObjAnimS32ToDoubleBias
  xoris r7, r7, 0x8000
  stw r7, 0x24(r1)
  lis r8, 0x4330
  stw r8, 0x20(r1)
  lfd f9, 0x20(r1)
  fsubs f10, f9, f11
  lha r7, 0x2(r9)
  xoris r7, r7, 0x8000
  stw r7, 0x1c(r1)
  stw r8, 0x18(r1)
  lfd f9, 0x18(r1)
  fsubs f9, f9, f11
  fsubs f9, f10, f9
  fmadds f1, f5, f9, f1
ObjAnim_SampleRootCurvePhase_L_8002FA1C:
  fadds f3, f3, f4
ObjAnim_SampleRootCurvePhase_L_8002FA20:
  cmpwi r11, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002F900
  cmplwi r4, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002FA34
  stfs f3, 0x0(r4)
ObjAnim_SampleRootCurvePhase_L_8002FA34:
  li r3, 0x1
  b ObjAnim_SampleRootCurvePhase_L_8002FA40
ObjAnim_SampleRootCurvePhase_L_8002FA3C:
  li r3, 0x0
ObjAnim_SampleRootCurvePhase_L_8002FA40:
  addi r1, r1, 0x30
  blr
}

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
asm int ObjAnim_AdvanceCurrentMove(f32 moveStepScale,f32 deltaTime,int objAnimArg,
                               ObjAnimEventList *events)
{
  nofralloc
  stwu r1, -0x60(r1)
  mflr r0
  stw r0, 0x64(r1)
  addi r11, r1, 0x60
  bl _savegpr_27
  li r11, 0x0
  lfs f0, lbl_803DE90C
  fcmpo cr0, f1, f0
  bge ObjAnim_AdvanceCurrentMove_L_8002FA70
  b ObjAnim_AdvanceCurrentMove_L_8002FA84
ObjAnim_AdvanceCurrentMove_L_8002FA70:
  lfs f0, gObjAnimProgressOne
  fcmpo cr0, f1, f0
  ble ObjAnim_AdvanceCurrentMove_L_8002FA80
  b ObjAnim_AdvanceCurrentMove_L_8002FA84
ObjAnim_AdvanceCurrentMove_L_8002FA80:
  fmr f0, f1
ObjAnim_AdvanceCurrentMove_L_8002FA84:
  lwz r5, 0x7c(r3)
  lbz r0, 0xad(r3)
  extsb r0, r0
  slwi r0, r0, 2
  lwzx r6, r5, r0
  lwz r5, 0x0(r6)
  lhz r0, 0xec(r5)
  cmplwi r0, 0x0
  bne ObjAnim_AdvanceCurrentMove_L_8002FAB0
  li r3, 0x0
  b ObjAnim_AdvanceCurrentMove_L_800302EC
ObjAnim_AdvanceCurrentMove_L_8002FAB0:
  lwz r8, 0x2c(r6)
  cmplwi r8, 0x0
  bne ObjAnim_AdvanceCurrentMove_L_8002FAC4
  li r3, 0x0
  b ObjAnim_AdvanceCurrentMove_L_800302EC
ObjAnim_AdvanceCurrentMove_L_8002FAC4:
  lfs f1, 0x14(r8)
  fmuls f1, f0, f1
  stfs f1, 0xc(r8)
  lhz r0, 0x58(r8)
  cmplwi r0, 0x0
  beq ObjAnim_AdvanceCurrentMove_L_8002FC70
  lbz r0, 0x63(r8)
  extsb r0, r0
  rlwinm r0, r0, 0, 28, 28
  cmpwi r0, 0x0
  beq ObjAnim_AdvanceCurrentMove_L_8002FAF8
  lfs f1, 0xc(r8)
  stfs f1, 0x10(r8)
ObjAnim_AdvanceCurrentMove_L_8002FAF8:
  lfs f3, 0x10(r8)
  lfs f1, 0x8(r8)
  fmadds f1, f3, f2, f1
  stfs f1, 0x8(r8)
  lfs f4, 0x18(r8)
  lbz r0, 0x61(r8)
  extsb r0, r0
  cmpwi r0, 0x0
  beq ObjAnim_AdvanceCurrentMove_L_8002FB7C
  lfs f1, 0x8(r8)
  lfs f3, gObjAnimProgressZero
  fcmpo cr0, f1, f3
  bge ObjAnim_AdvanceCurrentMove_L_8002FB48
  b ObjAnim_AdvanceCurrentMove_L_8002FB3C
ObjAnim_AdvanceCurrentMove_L_8002FB30:
  lfs f1, 0x8(r8)
  fadds f1, f1, f4
  stfs f1, 0x8(r8)
ObjAnim_AdvanceCurrentMove_L_8002FB3C:
  lfs f1, 0x8(r8)
  fcmpo cr0, f1, f3
  blt ObjAnim_AdvanceCurrentMove_L_8002FB30
ObjAnim_AdvanceCurrentMove_L_8002FB48:
  lfs f1, 0x8(r8)
  fcmpo cr0, f1, f4
  cror 2,1,2
  bne ObjAnim_AdvanceCurrentMove_L_8002FBA8
  b ObjAnim_AdvanceCurrentMove_L_8002FB68
ObjAnim_AdvanceCurrentMove_L_8002FB5C:
  lfs f1, 0x8(r8)
  fsubs f1, f1, f4
  stfs f1, 0x8(r8)
ObjAnim_AdvanceCurrentMove_L_8002FB68:
  lfs f1, 0x8(r8)
  fcmpo cr0, f1, f4
  cror 2,1,2
  beq ObjAnim_AdvanceCurrentMove_L_8002FB5C
  b ObjAnim_AdvanceCurrentMove_L_8002FBA8
ObjAnim_AdvanceCurrentMove_L_8002FB7C:
  lfs f3, 0x8(r8)
  lfs f1, gObjAnimProgressZero
  fcmpo cr0, f3, f1
  bge ObjAnim_AdvanceCurrentMove_L_8002FB90
  b ObjAnim_AdvanceCurrentMove_L_8002FBA4
ObjAnim_AdvanceCurrentMove_L_8002FB90:
  fcmpo cr0, f3, f4
  ble ObjAnim_AdvanceCurrentMove_L_8002FBA0
  fmr f1, f4
  b ObjAnim_AdvanceCurrentMove_L_8002FBA4
ObjAnim_AdvanceCurrentMove_L_8002FBA0:
  fmr f1, f3
ObjAnim_AdvanceCurrentMove_L_8002FBA4:
  stfs f1, 0x8(r8)
ObjAnim_AdvanceCurrentMove_L_8002FBA8:
  lbz r0, 0x63(r8)
  extsb r0, r0
  rlwinm r0, r0, 0, 30, 30
  cmpwi r0, 0x0
  bne ObjAnim_AdvanceCurrentMove_L_8002FC5C
  lhz r0, 0x5e(r8)
  lfd f3, gObjAnimU32ToDoubleBias
  stw r0, 0xc(r1)
  lis r5, 0x4330
  stw r5, 0x8(r1)
  lfd f1, 0x8(r1)
  fsubs f3, f1, f3
  lhz r0, 0x58(r8)
  lfd f4, gObjAnimS32ToDoubleBias
  xoris r0, r0, 0x8000
  stw r0, 0x14(r1)
  stw r5, 0x10(r1)
  lfd f1, 0x10(r1)
  fsubs f1, f1, f4
  fnmsubs f1, f3, f2, f1
  fctiwz f1, f1
  stfd f1, 0x18(r1)
  lwz r0, 0x1c(r1)
  cmpwi r0, 0x0
  bge ObjAnim_AdvanceCurrentMove_L_8002FC14
  lfs f3, gObjAnimProgressZero
  b ObjAnim_AdvanceCurrentMove_L_8002FC48
ObjAnim_AdvanceCurrentMove_L_8002FC14:
  xoris r0, r0, 0x8000
  stw r0, 0x24(r1)
  stw r5, 0x20(r1)
  lfd f1, 0x20(r1)
  fsubs f1, f1, f4
  lfs f3, gObjAnimEventStepScale
  fcmpo cr0, f1, f3
  ble ObjAnim_AdvanceCurrentMove_L_8002FC38
  b ObjAnim_AdvanceCurrentMove_L_8002FC48
ObjAnim_AdvanceCurrentMove_L_8002FC38:
  stw r0, 0x2c(r1)
  stw r5, 0x28(r1)
  lfd f1, 0x28(r1)
  fsubs f3, f1, f4
ObjAnim_AdvanceCurrentMove_L_8002FC48:
  fctiwz f1, f3
  stfd f1, 0x30(r1)
  lwz r0, 0x34(r1)
  clrlwi r0, r0, 16
  sth r0, 0x58(r8)
ObjAnim_AdvanceCurrentMove_L_8002FC5C:
  lhz r0, 0x58(r8)
  cmplwi r0, 0x0
  bne ObjAnim_AdvanceCurrentMove_L_8002FC70
  li r0, 0x0
  sth r0, 0x5c(r8)
ObjAnim_AdvanceCurrentMove_L_8002FC70:
  lfs f3, 0x98(r3)
  fmuls f1, f0, f2
  fadds f0, f3, f1
  stfs f0, 0x98(r3)
  lfs f0, 0x98(r3)
  lfs f4, gObjAnimProgressOne
  fcmpo cr0, f0, f4
  cror 2,1,2
  bne ObjAnim_AdvanceCurrentMove_L_8002FCD4
  lbz r0, 0x60(r8)
  extsb r0, r0
  cmpwi r0, 0x0
  beq ObjAnim_AdvanceCurrentMove_L_8002FCC8
  b ObjAnim_AdvanceCurrentMove_L_8002FCB4
ObjAnim_AdvanceCurrentMove_L_8002FCA8:
  lfs f0, 0x98(r3)
  fsubs f0, f0, f4
  stfs f0, 0x98(r3)
ObjAnim_AdvanceCurrentMove_L_8002FCB4:
  lfs f0, 0x98(r3)
  fcmpo cr0, f0, f4
  cror 2,1,2
  beq ObjAnim_AdvanceCurrentMove_L_8002FCA8
  b ObjAnim_AdvanceCurrentMove_L_8002FCCC
ObjAnim_AdvanceCurrentMove_L_8002FCC8:
  stfs f4, 0x98(r3)
ObjAnim_AdvanceCurrentMove_L_8002FCCC:
  li r11, 0x1
  b ObjAnim_AdvanceCurrentMove_L_8002FD18
ObjAnim_AdvanceCurrentMove_L_8002FCD4:
  lfs f2, gObjAnimProgressZero
  fcmpo cr0, f0, f2
  bge ObjAnim_AdvanceCurrentMove_L_8002FD18
  lbz r0, 0x60(r8)
  extsb r0, r0
  cmpwi r0, 0x0
  beq ObjAnim_AdvanceCurrentMove_L_8002FD10
  b ObjAnim_AdvanceCurrentMove_L_8002FD00
ObjAnim_AdvanceCurrentMove_L_8002FCF4:
  lfs f0, 0x98(r3)
  fadds f0, f0, f4
  stfs f0, 0x98(r3)
ObjAnim_AdvanceCurrentMove_L_8002FD00:
  lfs f0, 0x98(r3)
  fcmpo cr0, f0, f2
  blt ObjAnim_AdvanceCurrentMove_L_8002FCF4
  b ObjAnim_AdvanceCurrentMove_L_8002FD14
ObjAnim_AdvanceCurrentMove_L_8002FD10:
  stfs f2, 0x98(r3)
ObjAnim_AdvanceCurrentMove_L_8002FD14:
  li r11, 0x1
ObjAnim_AdvanceCurrentMove_L_8002FD18:
  cmplwi r4, 0x0
  bne ObjAnim_AdvanceCurrentMove_L_8002FD28
  mr r3, r11
  b ObjAnim_AdvanceCurrentMove_L_800302EC
ObjAnim_AdvanceCurrentMove_L_8002FD28:
  li r5, 0x0
  stb r5, 0x12(r4)
  lfs f0, gObjAnimProgressZero
  stfs f0, 0x8(r4)
  stfs f0, 0x4(r4)
  stfs f0, 0x0(r4)
  lwz r0, 0x60(r3)
  cmplwi r0, 0x0
  beq ObjAnim_AdvanceCurrentMove_L_8002FEC4
  stb r5, 0x1b(r4)
  lwz r5, 0x60(r3)
  lwz r0, 0x0(r5)
  srawi r7, r0, 1
  cmpwi r7, 0x0
  beq ObjAnim_AdvanceCurrentMove_L_8002FEC4
  lfs f2, gObjAnimEventFrameScale
  fmuls f0, f2, f3
  fctiwz f0, f0
  stfd f0, 0x30(r1)
  lwz r10, 0x34(r1)
  lfs f0, 0x98(r3)
  fmuls f0, f2, f0
  fctiwz f0, f0
  stfd f0, 0x28(r1)
  lwz r12, 0x2c(r1)
  li r30, 0x0
  cmpw r12, r10
  bge ObjAnim_AdvanceCurrentMove_L_8002FD9C
  ori r30, r30, 0x1
ObjAnim_AdvanceCurrentMove_L_8002FD9C:
  lfs f0, gObjAnimProgressZero
  fcmpo cr0, f1, f0
  bge ObjAnim_AdvanceCurrentMove_L_8002FDAC
  ori r30, r30, 0x2
ObjAnim_AdvanceCurrentMove_L_8002FDAC:
  li r9, 0x0
  li r5, 0x0
  b ObjAnim_AdvanceCurrentMove_L_8002FEAC
ObjAnim_AdvanceCurrentMove_L_8002FDB8:
  lwz r27, 0x60(r3)
  lwz r27, 0x4(r27)
  lhax r0, r27, r5
  clrlwi r31, r0, 23
  extrwi r0, r0, 7, 16
  cmpwi r0, 0x7f
  beq ObjAnim_AdvanceCurrentMove_L_8002FEA4
  cmpwi r30, 0x0
  bne ObjAnim_AdvanceCurrentMove_L_8002FE08
  cmpw r31, r10
  blt ObjAnim_AdvanceCurrentMove_L_8002FE08
  cmpw r31, r12
  bge ObjAnim_AdvanceCurrentMove_L_8002FE08
  extsb r29, r0
  lbz r28, 0x1b(r4)
  addi r27, r28, 0x1
  stb r27, 0x1b(r4)
  extsb r27, r28
  addi r27, r27, 0x13
  stbx r29, r4, r27
ObjAnim_AdvanceCurrentMove_L_8002FE08:
  cmpwi r30, 0x1
  bne ObjAnim_AdvanceCurrentMove_L_8002FE3C
  cmpw r31, r10
  bge ObjAnim_AdvanceCurrentMove_L_8002FE20
  cmpw r31, r12
  bge ObjAnim_AdvanceCurrentMove_L_8002FE3C
ObjAnim_AdvanceCurrentMove_L_8002FE20:
  extsb r29, r0
  lbz r28, 0x1b(r4)
  addi r27, r28, 0x1
  stb r27, 0x1b(r4)
  extsb r27, r28
  addi r27, r27, 0x13
  stbx r29, r4, r27
ObjAnim_AdvanceCurrentMove_L_8002FE3C:
  cmpwi r30, 0x3
  bne ObjAnim_AdvanceCurrentMove_L_8002FE70
  cmpw r31, r12
  ble ObjAnim_AdvanceCurrentMove_L_8002FE70
  cmpw r31, r10
  bgt ObjAnim_AdvanceCurrentMove_L_8002FE70
  extsb r27, r0
  lbz r28, 0x1b(r4)
  addi r29, r28, 0x1
  stb r29, 0x1b(r4)
  extsb r29, r28
  addi r29, r29, 0x13
  stbx r27, r4, r29
ObjAnim_AdvanceCurrentMove_L_8002FE70:
  cmpwi r30, 0x2
  bne ObjAnim_AdvanceCurrentMove_L_8002FEA4
  cmpw r31, r12
  bgt ObjAnim_AdvanceCurrentMove_L_8002FE88
  cmpw r31, r10
  bgt ObjAnim_AdvanceCurrentMove_L_8002FEA4
ObjAnim_AdvanceCurrentMove_L_8002FE88:
  extsb r29, r0
  lbz r31, 0x1b(r4)
  addi r0, r31, 0x1
  stb r0, 0x1b(r4)
  extsb r31, r31
  addi r0, r31, 0x13
  stbx r29, r4, r0
ObjAnim_AdvanceCurrentMove_L_8002FEA4:
  addi r5, r5, 0x2
  addi r9, r9, 0x1
ObjAnim_AdvanceCurrentMove_L_8002FEAC:
  cmpw r9, r7
  bge ObjAnim_AdvanceCurrentMove_L_8002FEC4
  lbz r0, 0x1b(r4)
  extsb r0, r0
  cmpwi r0, 0x8
  blt ObjAnim_AdvanceCurrentMove_L_8002FDB8
ObjAnim_AdvanceCurrentMove_L_8002FEC4:
  lwz r5, 0x0(r6)
  lhz r0, 0x2(r5)
  rlwinm r0, r0, 0, 25, 25
  cmpwi r0, 0x0
  beq ObjAnim_AdvanceCurrentMove_L_8002FEF0
  lhz r0, 0x44(r8)
  slwi r0, r0, 2
  add r5, r8, r0
  lwz r5, 0x1c(r5)
  addi r5, r5, 0x80
  b ObjAnim_AdvanceCurrentMove_L_8002FF00
ObjAnim_AdvanceCurrentMove_L_8002FEF0:
  lwz r5, 0x64(r5)
  lhz r0, 0x44(r8)
  slwi r0, r0, 2
  lwzx r5, r5, r0
ObjAnim_AdvanceCurrentMove_L_8002FF00:
  lha r0, 0x4(r5)
  cmpwi r0, 0x0
  beq ObjAnim_AdvanceCurrentMove_L_800302E0
  li r0, 0x1
  stb r0, 0x12(r4)
  lha r0, 0x4(r5)
  add r12, r5, r0
  lfs f2, 0x0(r12)
  lfs f0, 0x8(r3)
  fmuls f5, f2, f0
  lha r5, 0x4(r12)
  subi r9, r5, 0x1
  addi r12, r12, 0x6
  lfd f4, gObjAnimS32ToDoubleBias
  xoris r0, r9, 0x8000
  stw r0, 0x34(r1)
  lis r10, 0x4330
  stw r10, 0x30(r1)
  lfd f0, 0x30(r1)
  fsubs f6, f0, f4
  fmuls f2, f6, f3
  fctiwz f0, f2
  stfd f0, 0x28(r1)
  lwz r0, 0x2c(r1)
  xoris r5, r0, 0x8000
  stw r5, 0x24(r1)
  stw r10, 0x20(r1)
  lfd f0, 0x20(r1)
  fsubs f0, f0, f4
  fsubs f0, f2, f0
  lfs f2, 0x98(r3)
  fmuls f6, f6, f2
  fctiwz f2, f6
  stfd f2, 0x18(r1)
  lwz r7, 0x1c(r1)
  xoris r5, r7, 0x8000
  stw r5, 0x14(r1)
  stw r10, 0x10(r1)
  lfd f2, 0x10(r1)
  fsubs f2, f2, f4
  fsubs f2, f6, f2
  li r31, 0x0
  lhz r5, 0x5a(r8)
  cmplwi r5, 0x0
  beq ObjAnim_AdvanceCurrentMove_L_80030024
  lfd f6, gObjAnimU32ToDoubleBias
  stw r5, 0x34(r1)
  stw r10, 0x30(r1)
  lfd f4, 0x30(r1)
  fsubs f6, f4, f6
  lfs f4, gObjAnimEventStepScale
  fdivs f6, f6, f4
  lfs f4, gObjAnimProgressOne
  fsubs f7, f4, f6
  lwz r6, 0x0(r6)
  lhz r5, 0x2(r6)
  rlwinm r5, r5, 0, 25, 25
  cmpwi r5, 0x0
  beq ObjAnim_AdvanceCurrentMove_L_80030004
  lhz r5, 0x48(r8)
  slwi r5, r5, 2
  add r5, r8, r5
  lwz r5, 0x24(r5)
  addi r6, r5, 0x80
  b ObjAnim_AdvanceCurrentMove_L_80030014
ObjAnim_AdvanceCurrentMove_L_80030004:
  lwz r6, 0x64(r6)
  lhz r5, 0x48(r8)
  slwi r5, r5, 2
  lwzx r6, r6, r5
ObjAnim_AdvanceCurrentMove_L_80030014:
  lha r5, 0x4(r6)
  add r31, r6, r5
  addi r31, r31, 0x6
  b ObjAnim_AdvanceCurrentMove_L_8003002C
ObjAnim_AdvanceCurrentMove_L_80030024:
  lfs f6, gObjAnimProgressZero
  lfs f7, gObjAnimProgressOne
ObjAnim_AdvanceCurrentMove_L_8003002C:
  li r10, 0x0
  mr r5, r4
  slwi r6, r0, 1
  slwi r7, r7, 1
  slwi r8, r9, 1
  addi r0, r9, 0x1
  slwi r0, r0, 1
ObjAnim_AdvanceCurrentMove_L_80030048:
  lha r9, 0x0(r12)
  cmpwi r9, 0x0
  beq ObjAnim_AdvanceCurrentMove_L_8003029C
  addi r12, r12, 0x2
  cmplwi r31, 0x0
  beq ObjAnim_AdvanceCurrentMove_L_80030064
  addi r31, r31, 0x2
ObjAnim_AdvanceCurrentMove_L_80030064:
  add r27, r6, r12
  lha r9, 0x0(r27)
  lfd f8, gObjAnimS32ToDoubleBias
  xoris r9, r9, 0x8000
  stw r9, 0x34(r1)
  lis r30, 0x4330
  stw r30, 0x30(r1)
  lfd f4, 0x30(r1)
  fsubs f4, f4, f8
  fmuls f9, f7, f4
  cmplwi r31, 0x0
  beq ObjAnim_AdvanceCurrentMove_L_800300B0
  lhax r9, r6, r31
  xoris r9, r9, 0x8000
  stw r9, 0x2c(r1)
  stw r30, 0x28(r1)
  lfd f4, 0x28(r1)
  fsubs f4, f4, f8
  fmadds f9, f6, f4, f9
ObjAnim_AdvanceCurrentMove_L_800300B0:
  lha r9, 0x2(r27)
  lfd f8, gObjAnimS32ToDoubleBias
  xoris r9, r9, 0x8000
  stw r9, 0x24(r1)
  lis r30, 0x4330
  stw r30, 0x20(r1)
  lfd f4, 0x20(r1)
  fsubs f4, f4, f8
  fmuls f10, f7, f4
  cmplwi r31, 0x0
  beq ObjAnim_AdvanceCurrentMove_L_800300FC
  addi r9, r31, 0x2
  lhax r9, r6, r9
  xoris r9, r9, 0x8000
  stw r9, 0x1c(r1)
  stw r30, 0x18(r1)
  lfd f4, 0x18(r1)
  fsubs f4, f4, f8
  fmadds f10, f6, f4, f10
ObjAnim_AdvanceCurrentMove_L_800300FC:
  fsubs f4, f10, f9
  fmadds f4, f0, f4, f9
  add r27, r7, r12
  lha r9, 0x0(r27)
  lfd f9, gObjAnimS32ToDoubleBias
  xoris r9, r9, 0x8000
  stw r9, 0x14(r1)
  lis r30, 0x4330
  stw r30, 0x10(r1)
  lfd f8, 0x10(r1)
  fsubs f8, f8, f9
  fmuls f10, f7, f8
  cmplwi r31, 0x0
  beq ObjAnim_AdvanceCurrentMove_L_80030150
  lhax r9, r7, r31
  xoris r9, r9, 0x8000
  stw r9, 0xc(r1)
  stw r30, 0x8(r1)
  lfd f8, 0x8(r1)
  fsubs f8, f8, f9
  fmadds f10, f6, f8, f10
ObjAnim_AdvanceCurrentMove_L_80030150:
  lha r9, 0x2(r27)
  lfd f9, gObjAnimS32ToDoubleBias
  xoris r9, r9, 0x8000
  stw r9, 0x3c(r1)
  lis r30, 0x4330
  stw r30, 0x38(r1)
  lfd f8, 0x38(r1)
  fsubs f8, f8, f9
  fmuls f11, f7, f8
  cmplwi r31, 0x0
  beq ObjAnim_AdvanceCurrentMove_L_8003019C
  addi r9, r31, 0x2
  lhax r9, r7, r9
  xoris r9, r9, 0x8000
  stw r9, 0x44(r1)
  stw r30, 0x40(r1)
  lfd f8, 0x40(r1)
  fsubs f8, f8, f9
  fmadds f11, f6, f8, f11
ObjAnim_AdvanceCurrentMove_L_8003019C:
  fsubs f8, f11, f10
  fmadds f10, f2, f8, f10
  lfs f8, gObjAnimProgressZero
  fcmpo cr0, f1, f8
  ble ObjAnim_AdvanceCurrentMove_L_8003020C
  lfs f8, 0x98(r3)
  fcmpo cr0, f8, f3
  bge ObjAnim_AdvanceCurrentMove_L_80030204
  lhax r9, r8, r12
  lfd f9, gObjAnimS32ToDoubleBias
  xoris r9, r9, 0x8000
  stw r9, 0x44(r1)
  lis r30, 0x4330
  stw r30, 0x40(r1)
  lfd f8, 0x40(r1)
  fsubs f8, f8, f9
  fmadds f10, f7, f8, f10
  cmplwi r31, 0x0
  beq ObjAnim_AdvanceCurrentMove_L_80030204
  lhax r9, r8, r31
  xoris r9, r9, 0x8000
  stw r9, 0x44(r1)
  stw r30, 0x40(r1)
  lfd f8, 0x40(r1)
  fsubs f8, f8, f9
  fmadds f10, f6, f8, f10
ObjAnim_AdvanceCurrentMove_L_80030204:
  fsubs f4, f10, f4
  b ObjAnim_AdvanceCurrentMove_L_80030264
ObjAnim_AdvanceCurrentMove_L_8003020C:
  lfs f8, 0x98(r3)
  fcmpo cr0, f8, f3
  ble ObjAnim_AdvanceCurrentMove_L_80030260
  lhax r9, r8, r12
  lfd f9, gObjAnimS32ToDoubleBias
  xoris r9, r9, 0x8000
  stw r9, 0x44(r1)
  lis r30, 0x4330
  stw r30, 0x40(r1)
  lfd f8, 0x40(r1)
  fsubs f8, f8, f9
  fnmsubs f10, f7, f8, f10
  cmplwi r31, 0x0
  beq ObjAnim_AdvanceCurrentMove_L_80030260
  lhax r9, r8, r31
  xoris r9, r9, 0x8000
  stw r9, 0x44(r1)
  stw r30, 0x40(r1)
  lfd f8, 0x40(r1)
  fsubs f8, f8, f9
  fmadds f10, f6, f8, f10
ObjAnim_AdvanceCurrentMove_L_80030260:
  fsubs f4, f10, f4
ObjAnim_AdvanceCurrentMove_L_80030264:
  cmpwi r10, 0x3
  bge ObjAnim_AdvanceCurrentMove_L_80030278
  fmuls f4, f4, f5
  stfs f4, 0x0(r4)
  b ObjAnim_AdvanceCurrentMove_L_80030288
ObjAnim_AdvanceCurrentMove_L_80030278:
  fctiwz f4, f4
  stfd f4, 0x40(r1)
  lwz r9, 0x44(r1)
  sth r9, 0x6(r5)
ObjAnim_AdvanceCurrentMove_L_80030288:
  add r12, r12, r0
  cmplwi r31, 0x0
  beq ObjAnim_AdvanceCurrentMove_L_800302C8
  add r31, r31, r0
  b ObjAnim_AdvanceCurrentMove_L_800302C8
ObjAnim_AdvanceCurrentMove_L_8003029C:
  addi r12, r12, 0x2
  cmplwi r31, 0x0
  beq ObjAnim_AdvanceCurrentMove_L_800302AC
  addi r31, r31, 0x2
ObjAnim_AdvanceCurrentMove_L_800302AC:
  cmpwi r10, 0x3
  bge ObjAnim_AdvanceCurrentMove_L_800302C0
  lfs f4, gObjAnimProgressZero
  stfs f4, 0x0(r4)
  b ObjAnim_AdvanceCurrentMove_L_800302C8
ObjAnim_AdvanceCurrentMove_L_800302C0:
  li r9, 0x0
  sth r9, 0x6(r5)
ObjAnim_AdvanceCurrentMove_L_800302C8:
  addi r4, r4, 0x4
  addi r5, r5, 0x2
  addi r10, r10, 0x1
  cmpwi r10, 0x6
  blt ObjAnim_AdvanceCurrentMove_L_80030048
  b ObjAnim_AdvanceCurrentMove_L_800302E8
ObjAnim_AdvanceCurrentMove_L_800302E0:
  li r0, 0x0
  stb r0, 0x12(r4)
ObjAnim_AdvanceCurrentMove_L_800302E8:
  mr r3, r11
ObjAnim_AdvanceCurrentMove_L_800302EC:
  addi r11, r1, 0x60
  bl _restgpr_27
  lwz r0, 0x64(r1)
  mtlr r0
  addi r1, r1, 0x60
  blr
}

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
int ObjAnim_SetMoveProgress(f32 moveProgress,ObjAnimComponent *objAnim)
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
int ObjAnim_SetCurrentMove(int objAnimArg,int moveId,f32 moveProgress,int flags)
{
  ObjAnimComponent *objAnim;
  ObjAnimBank *bank;
  ObjAnimDef *animDef;
  ObjAnimState *state;
  s16 previousMove;
  u8 moveChanged;
  int requestedMoveId;
  int frameStep;
  ObjAnimMoveData *moveData;
  float eventStepFrames;
  ObjHitReactState *hitState;

  objAnim = (ObjAnimComponent *)objAnimArg;
  requestedMoveId = moveId;
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
    ObjHitReact_LoadMoveEntries(objAnimArg,bank,(int)objAnim->objType,hitState,requestedMoveId,0);
  }
  if (objAnim->eventTable != (ObjAnimEventTable *)0x0) {
    ObjAnim_LoadMoveEvents(objAnimArg,(int)objAnim->objType,objAnim->eventTable,requestedMoveId,0);
  }
  previousMove = objAnim->currentMove;
  moveChanged = previousMove != requestedMoveId;
  objAnim->currentMove = (s16)requestedMoveId;
  moveId =
      animDef->moveGroupBaseIndices[(s32)requestedMoveId >> OBJANIM_MOVE_GROUP_SHIFT] +
      (requestedMoveId & OBJANIM_MOVE_INDEX_MASK);
  if (moveId >= animDef->moveCount) {
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
