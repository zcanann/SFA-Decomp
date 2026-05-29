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
extern f32 gObjAnimSetMoveProgressMax;
extern f32 gObjAnimMoveStepScaleMin;

static inline ObjAnimRootCurve *ObjAnim_GetMoveRootCurve(ObjAnimDef *animDef,ObjAnimState *state,u16 slot)
{
  ObjAnimMoveData *moveData;

  moveData = ObjAnim_GetMoveData(animDef,state,slot);
  if (moveData->rootCurveOffset == 0) {
    return NULL;
  }
  return (ObjAnimRootCurve *)((u8 *)moveData + moveData->rootCurveOffset);
}

static inline ObjAnimRootCurve *ObjAnim_GetBlendMoveRootCurve(ObjAnimDef *animDef,ObjAnimState *state,u16 slot)
{
  ObjAnimMoveData *moveData;

  moveData = ObjAnim_GetBlendMoveData(animDef,state,slot);
  if (moveData->rootCurveOffset == 0) {
    return NULL;
  }
  return (ObjAnimRootCurve *)((u8 *)moveData + moveData->rootCurveOffset);
}

static inline s16 *ObjAnim_FindFirstRootTranslationAxis(ObjAnimRootCurve *curve)
{
  s16 *axis;
  int axisIndex;

  axis = (s16 *)((u8 *)curve + OBJANIM_ROOT_CURVE_AXIS_DATA_OFFSET);
  for (axisIndex = 0; axisIndex < OBJANIM_ROOT_CURVE_TRANSLATION_AXIS_COUNT; axisIndex++) {
    if (*axis != 0) {
      return axis;
    }
    axis++;
  }
  return NULL;
}

static inline s16 ObjAnim_ReadRootAxisSample(s16 *axis,int sampleIndex)
{
  return axis[sampleIndex + 1];
}

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
  int eventStateValue;
  int moveIndex;
  ObjAnimMoveData *moveData;
  int frameType;
  float frameValue;

  eventStateValue = eventState;
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
      state->eventState = (u16)eventStateValue;
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
int Object_ObjAnimAdvanceMove(f32 moveStepScale,f32 deltaTime,int objAnimArg,
                              ObjAnimEventList *events)
{
  ObjAnimComponent *objAnim;
  ObjAnimBank *bank;
  ObjAnimState *state;
  ObjAnimEventTable *eventTable;
  f32 previousProgress;
  f32 progressDelta;
  f32 prevSegmentLength;
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

  objAnim = (ObjAnimComponent *)objAnimArg;
  wrapped = 0;
  bank = ObjAnim_GetActiveBank(objAnim);
  if (bank->animDef->moveCount == 0) {
    return 0;
  }

  state = bank->activeState;
  state->step = moveStepScale * state->segmentLength;
  if (state->eventCountdown != 0) {
    if ((state->flags & OBJANIM_STATE_FLAG_REFRESH_SAVED_STEP) != 0) {
      state->savedStep = state->step;
    }
    state->progress += state->savedStep * deltaTime;
    prevSegmentLength = state->prevSegmentLength;
    if (state->prevFrameType != OBJANIM_FRAME_TYPE_CLAMPED) {
      while (state->progress < gObjAnimProgressZero) {
        state->progress += prevSegmentLength;
      }
      while (state->progress >= prevSegmentLength) {
        state->progress -= prevSegmentLength;
      }
    }
    else {
      value = state->progress;
      if (value < gObjAnimProgressZero) {
        value = gObjAnimProgressZero;
      } else if (value > prevSegmentLength) {
        value = prevSegmentLength;
      }
      state->progress = value;
    }

    if ((state->flags & OBJANIM_STATE_FLAG_HOLD_EVENT_COUNTDOWN) == 0) {
      countdown =
          (int)((f32)(s32)state->eventCountdown - ((f32)state->eventStep * deltaTime));
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

    if (scanMode == OBJANIM_EVENT_SCAN_FORWARD) {
      if ((previousFrame <= eventFrame) && (eventFrame < currentFrame)) {
        events->triggeredIds[events->triggerCount++] = (s8)eventId;
      }
    }
    if (scanMode == OBJANIM_EVENT_SCAN_WRAPPED) {
      if ((eventFrame >= previousFrame) || (eventFrame < currentFrame)) {
        events->triggeredIds[events->triggerCount++] = (s8)eventId;
      }
    }
    if (scanMode == OBJANIM_EVENT_SCAN_REVERSE_WRAPPED) {
      if ((eventFrame > currentFrame) && (eventFrame <= previousFrame)) {
        events->triggeredIds[events->triggerCount++] = (s8)eventId;
      }
    }
    if (scanMode == OBJANIM_EVENT_SCAN_REVERSE) {
      if ((eventFrame > currentFrame) || (eventFrame <= previousFrame)) {
        events->triggeredIds[events->triggerCount++] = (s8)eventId;
      }
    }
  }

  return wrapped;
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
int Object_ObjAnimSetMoveProgress(f32 moveProgress,ObjAnimComponent *objAnim)
{
  if (moveProgress > gObjAnimSetMoveProgressMax) {
    moveProgress = gObjAnimSetMoveProgressMax;
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
#pragma scheduling off
#pragma peephole off
int ObjAnim_SampleRootCurvePhase(f32 distance,ObjAnimComponent *objAnim,float *phaseOut)
{
  ObjAnimBank *bank;
  ObjAnimDef *animDef;
  ObjAnimState *state;
  ObjAnimMoveData *moveData;
  ObjAnimRootCurve *curve;
  ObjAnimRootCurve *blendCurve;
  ObjModelInstance *model;
  s16 *axis;
  s16 *blendSamples;
  f32 rootScale;
  f32 blendScale;
  f32 blendWeight;
  f32 moveWeight;
  f32 targetDistance;
  f32 sampleCount;
  f32 phaseStep;
  f32 sampleProgress;
  f32 sampleFraction;
  f32 previousDistance;
  f32 nextDistance;
  f32 phase;
  int segmentCount;
  int sampleIndex;
  int lastSample;

  bank = ObjAnim_GetActiveBank(objAnim);
  animDef = bank->animDef;
  if (animDef->moveCount == 0) {
    return 0;
  }

  state = bank->currentState;
  model = objAnim->modelInstance;
  targetDistance = distance * (objAnim->rootMotionScale / model->rootMotionScaleBase);
  blendSamples = NULL;

  if (state->eventState != 0) {
    blendWeight = (f32)state->eventState / gObjAnimEventStepScale;
    moveWeight = gObjAnimProgressOne - blendWeight;
    moveData = ObjAnim_GetBlendMoveData(animDef,state,state->blendCacheSlot);
    if (moveData->rootCurveOffset != 0) {
      blendCurve = (ObjAnimRootCurve *)((u8 *)moveData + moveData->rootCurveOffset);
      blendScale = blendCurve->scale * objAnim->rootMotionScale;
      blendSamples = (s16 *)((u8 *)blendCurve + OBJANIM_ROOT_CURVE_AXIS_DATA_OFFSET);
      if (*blendSamples == 0) {
        blendSamples++;
        if (*blendSamples == 0) {
          blendSamples++;
          if (*blendSamples == 0) {
            blendSamples = NULL;
          }
        }
      }
      if (blendSamples != NULL) {
        blendSamples++;
      }
    }
  }

  moveData = ObjAnim_GetMoveData(animDef,state,state->moveCacheSlot);
  if (moveData->rootCurveOffset == 0) {
    return 0;
  }
  curve = (ObjAnimRootCurve *)((u8 *)moveData + moveData->rootCurveOffset);

  rootScale = curve->scale * objAnim->rootMotionScale;
  segmentCount = curve->sampleCount - 1;
  axis = (s16 *)((u8 *)curve + OBJANIM_ROOT_CURVE_AXIS_DATA_OFFSET);
  if (*axis == 0) {
    axis++;
    if (*axis == 0) {
      axis++;
    }
  }
  if (*axis == 0) {
    return 0;
  }

  lastSample = ObjAnim_ReadRootAxisSample(axis,segmentCount);
  if (lastSample < 0) {
    rootScale = -rootScale;
  }
  if (lastSample == 0) {
    return 0;
  }

  sampleCount = (f32)segmentCount;
  phaseStep = gObjAnimProgressOne / sampleCount;
  sampleProgress = sampleCount * objAnim->currentMoveProgress;
  sampleIndex = (int)sampleProgress;
  sampleFraction = sampleProgress - (f32)sampleIndex;

  if (blendSamples != NULL && blendSamples[segmentCount] < 0) {
    blendScale = -blendScale;
  }

  if (blendSamples != NULL) {
    previousDistance =
        (rootScale * moveWeight * (f32)ObjAnim_ReadRootAxisSample(axis,sampleIndex)) +
        (blendScale * blendWeight * (f32)blendSamples[sampleIndex]);
    nextDistance =
        (rootScale * moveWeight * (f32)ObjAnim_ReadRootAxisSample(axis,sampleIndex + 1)) +
        (blendScale * blendWeight * (f32)blendSamples[sampleIndex + 1]);
  }
  else {
    previousDistance = rootScale * (f32)ObjAnim_ReadRootAxisSample(axis,sampleIndex);
    nextDistance = rootScale * (f32)ObjAnim_ReadRootAxisSample(axis,sampleIndex + 1);
  }

  targetDistance += previousDistance + sampleFraction * (nextDistance - previousDistance);
  phase = phaseStep - (phaseStep * sampleFraction);
  while (nextDistance <= targetDistance) {
    sampleIndex++;
    if (sampleIndex >= segmentCount) {
      sampleIndex = 0;
    }
    previousDistance = nextDistance;
    if (blendSamples != NULL) {
      nextDistance +=
          (rootScale * moveWeight *
           ((f32)ObjAnim_ReadRootAxisSample(axis,sampleIndex + 1) -
            (f32)ObjAnim_ReadRootAxisSample(axis,sampleIndex))) +
          (blendScale * blendWeight *
           ((f32)blendSamples[sampleIndex + 1] - (f32)blendSamples[sampleIndex]));
    }
    else {
      nextDistance +=
          rootScale *
          ((f32)ObjAnim_ReadRootAxisSample(axis,sampleIndex + 1) -
           (f32)ObjAnim_ReadRootAxisSample(axis,sampleIndex));
    }
    phase += phaseStep;
  }

  phase -= phaseStep * ((nextDistance - targetDistance) / (nextDistance - previousDistance));
  if (phaseOut != NULL) {
    *phaseOut = phase;
  }
  return 1;
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
int ObjAnim_AdvanceCurrentMove(f32 moveStepScale,f32 deltaTime,int objAnimArg,
                               ObjAnimEventList *events)
{
  ObjAnimComponent *objAnim;
  ObjAnimBank *bank;
  ObjAnimDef *animDef;
  ObjAnimState *state;
  ObjAnimEventTable *eventTable;
  ObjAnimRootCurve *curve;
  ObjAnimRootCurve *blendCurve;
  s16 *axis;
  s16 *blendAxis;
  f32 previousProgress;
  f32 progressDelta;
  f32 clampedStepScale;
  f32 prevSegmentLength;
  f32 value;
  f32 previousAxisValue;
  f32 previousAxisNextValue;
  f32 currentAxisValue;
  f32 currentAxisNextValue;
  f32 previousInterp;
  f32 currentInterp;
  f32 previousScaledSample;
  f32 currentScaledSample;
  f32 previousFraction;
  f32 currentFraction;
  f32 rootScale;
  f32 blendWeight;
  f32 moveWeight;
  int wrapped;
  int countdown;
  int previousFrame;
  int currentFrame;
  int scanMode;
  int eventCount;
  int eventIndex;
  int axisIndex;
  int sampleCount;
  int segmentCount;
  int previousSampleIndex;
  int currentSampleIndex;
  s16 eventEntry;
  int eventFrame;
  int eventId;

  objAnim = (ObjAnimComponent *)objAnimArg;
  clampedStepScale = gObjAnimMoveStepScaleMin;
  if (moveStepScale >= gObjAnimMoveStepScaleMin) {
    clampedStepScale = gObjAnimProgressOne;
    if (moveStepScale <= gObjAnimProgressOne) {
      clampedStepScale = moveStepScale;
    }
  }

  bank = ObjAnim_GetActiveBank(objAnim);
  animDef = bank->animDef;
  if (animDef->moveCount == 0) {
    return 0;
  }

  state = bank->currentState;
  if (state == NULL) {
    return 0;
  }

  wrapped = 0;
  state->step = clampedStepScale * state->segmentLength;
  if (state->eventCountdown != 0) {
    if ((state->flags & OBJANIM_STATE_FLAG_REFRESH_SAVED_STEP) != 0) {
      state->savedStep = state->step;
    }
    state->progress += state->savedStep * deltaTime;
    prevSegmentLength = state->prevSegmentLength;
    if (state->prevFrameType != OBJANIM_FRAME_TYPE_CLAMPED) {
      while (state->progress < gObjAnimProgressZero) {
        state->progress += prevSegmentLength;
      }
      while (state->progress >= prevSegmentLength) {
        state->progress -= prevSegmentLength;
      }
    } else {
      value = state->progress;
      if (value < gObjAnimProgressZero) {
        value = gObjAnimProgressZero;
      } else if (value > prevSegmentLength) {
        value = prevSegmentLength;
      }
      state->progress = value;
    }

    if ((state->flags & OBJANIM_STATE_FLAG_HOLD_EVENT_COUNTDOWN) == 0) {
      countdown = (int)((f32)(s32)state->eventCountdown - ((f32)state->eventStep * deltaTime));
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

  previousProgress = objAnim->currentMoveProgress;
  progressDelta = clampedStepScale * deltaTime;
  objAnim->currentMoveProgress = previousProgress + progressDelta;
  if (objAnim->currentMoveProgress >= gObjAnimProgressOne) {
    if (state->frameType != OBJANIM_FRAME_TYPE_CLAMPED) {
      while (objAnim->currentMoveProgress >= gObjAnimProgressOne) {
        objAnim->currentMoveProgress -= gObjAnimProgressOne;
      }
    }
    else {
      objAnim->currentMoveProgress = gObjAnimProgressOne;
    }
    wrapped = 1;
  }
  else if (objAnim->currentMoveProgress < gObjAnimProgressZero) {
    if (state->frameType != OBJANIM_FRAME_TYPE_CLAMPED) {
      while (objAnim->currentMoveProgress < gObjAnimProgressZero) {
        objAnim->currentMoveProgress += gObjAnimProgressOne;
      }
    }
    else {
      objAnim->currentMoveProgress = gObjAnimProgressZero;
    }
    wrapped = 1;
  }

  if (events == NULL) {
    return wrapped;
  }

  events->rootCurveValid = 0;
  events->rootDeltaX = gObjAnimProgressZero;
  events->rootDeltaY = gObjAnimProgressZero;
  events->rootDeltaZ = gObjAnimProgressZero;
  eventTable = objAnim->eventTable;
  if (eventTable != NULL) {
    events->triggerCount = 0;
    eventCount = eventTable->byteCount >> 1;
    if (eventCount != 0) {
      previousFrame = (int)(gObjAnimEventFrameScale * previousProgress);
      currentFrame = (int)(gObjAnimEventFrameScale * objAnim->currentMoveProgress);
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

        if (scanMode == OBJANIM_EVENT_SCAN_FORWARD) {
          if ((previousFrame <= eventFrame) && (eventFrame < currentFrame)) {
            events->triggeredIds[events->triggerCount++] = (s8)eventId;
          }
        }
        if (scanMode == OBJANIM_EVENT_SCAN_WRAPPED) {
          if ((eventFrame >= previousFrame) || (eventFrame < currentFrame)) {
            events->triggeredIds[events->triggerCount++] = (s8)eventId;
          }
        }
        if (scanMode == OBJANIM_EVENT_SCAN_REVERSE_WRAPPED) {
          if ((eventFrame > currentFrame) && (eventFrame <= previousFrame)) {
            events->triggeredIds[events->triggerCount++] = (s8)eventId;
          }
        }
        if (scanMode == OBJANIM_EVENT_SCAN_REVERSE) {
          if ((eventFrame > currentFrame) || (eventFrame <= previousFrame)) {
            events->triggeredIds[events->triggerCount++] = (s8)eventId;
          }
        }
      }
    }
  }

  curve = ObjAnim_GetMoveRootCurve(animDef,state,state->moveCacheSlot);
  if (curve == NULL) {
    events->rootCurveValid = 0;
    return wrapped;
  }

  events->rootCurveValid = 1;
  rootScale = curve->scale * objAnim->rootMotionScale;
  sampleCount = curve->sampleCount;
  segmentCount = sampleCount - 1;
  axis = (s16 *)((u8 *)curve + OBJANIM_ROOT_CURVE_AXIS_DATA_OFFSET);
  previousScaledSample = (f32)segmentCount * previousProgress;
  previousSampleIndex = (int)previousScaledSample;
  previousFraction = previousScaledSample - (f32)previousSampleIndex;
  currentScaledSample = (f32)segmentCount * objAnim->currentMoveProgress;
  currentSampleIndex = (int)currentScaledSample;
  currentFraction = currentScaledSample - (f32)currentSampleIndex;

  blendAxis = NULL;
  if (state->eventState != 0) {
    blendWeight = (f32)state->eventState / gObjAnimEventStepScale;
    moveWeight = gObjAnimProgressOne - blendWeight;
    blendCurve = ObjAnim_GetBlendMoveRootCurve(animDef,state,state->blendCacheSlot);
    if (blendCurve != NULL) {
      blendAxis = (s16 *)((u8 *)blendCurve + OBJANIM_ROOT_CURVE_AXIS_DATA_OFFSET);
    }
  }
  else {
    blendWeight = gObjAnimProgressZero;
    moveWeight = gObjAnimProgressOne;
  }

  for (axisIndex = 0; axisIndex < OBJANIM_ROOT_CURVE_AXIS_COUNT; axisIndex++) {
    if (*axis == 0) {
      axis++;
      if (blendAxis != NULL) {
        blendAxis++;
      }
      if (axisIndex < OBJANIM_ROOT_CURVE_TRANSLATION_AXIS_COUNT) {
        (&events->rootDeltaX)[axisIndex] = gObjAnimProgressZero;
      }
      else {
        (&events->rootYaw)[axisIndex - OBJANIM_ROOT_CURVE_TRANSLATION_AXIS_COUNT] = 0;
      }
    }
    else {
      axis++;
      if (blendAxis != NULL) {
        blendAxis++;
      }
      previousAxisValue = moveWeight * (f32)axis[previousSampleIndex];
      if (blendAxis != NULL) {
        previousAxisValue += blendWeight * (f32)blendAxis[previousSampleIndex];
      }
      previousAxisNextValue = moveWeight * (f32)axis[previousSampleIndex + 1];
      if (blendAxis != NULL) {
        previousAxisNextValue += blendWeight * (f32)blendAxis[previousSampleIndex + 1];
      }
      previousInterp = previousAxisValue +
                       previousFraction * (previousAxisNextValue - previousAxisValue);

      currentAxisValue = moveWeight * (f32)axis[currentSampleIndex];
      if (blendAxis != NULL) {
        currentAxisValue += blendWeight * (f32)blendAxis[currentSampleIndex];
      }
      currentAxisNextValue = moveWeight * (f32)axis[currentSampleIndex + 1];
      if (blendAxis != NULL) {
        currentAxisNextValue += blendWeight * (f32)blendAxis[currentSampleIndex + 1];
      }
      currentInterp = currentAxisValue +
                      currentFraction * (currentAxisNextValue - currentAxisValue);

      if (progressDelta > gObjAnimProgressZero) {
        if (objAnim->currentMoveProgress < previousProgress) {
          currentInterp += moveWeight * (f32)axis[segmentCount];
          if (blendAxis != NULL) {
            currentInterp += blendWeight * (f32)blendAxis[segmentCount];
          }
        }
      }
      else if (objAnim->currentMoveProgress > previousProgress) {
        currentInterp -= moveWeight * (f32)axis[segmentCount];
        if (blendAxis != NULL) {
          currentInterp += blendWeight * (f32)blendAxis[segmentCount];
        }
      }

      value = currentInterp - previousInterp;
      if (axisIndex < OBJANIM_ROOT_CURVE_TRANSLATION_AXIS_COUNT) {
        (&events->rootDeltaX)[axisIndex] = value * rootScale;
      }
      else {
        (&events->rootYaw)[axisIndex - OBJANIM_ROOT_CURVE_TRANSLATION_AXIS_COUNT] =
            (s16)(int)value;
      }

      axis += sampleCount;
      if (blendAxis != NULL) {
        blendAxis += sampleCount;
      }
    }
  }

  return wrapped;
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
int ObjAnim_SetMoveProgress(f32 moveProgress,ObjAnimComponent *objAnim)
{
  if (moveProgress > gObjAnimSetMoveProgressMax) {
    moveProgress = gObjAnimSetMoveProgressMax;
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
