#include "dolphin/os.h"
#include "main/objHitReact.h"
#include "main/objanim_internal.h"

static inline s16* ObjAnim_FindFirstRootTranslationAxis(ObjAnimRootCurve* curve)
{
    s16* axis;
    int axisIndex;

    axis = ObjAnim_GetRootCurveAxisData(curve);
    for (axisIndex = 0; axisIndex < OBJANIM_ROOT_CURVE_TRANSLATION_AXIS_COUNT; axisIndex++)
    {
        if (*axis != 0)
        {
            return axis;
        }
        axis++;
    }
    return NULL;
}

static inline s16 ObjAnim_ReadRootAxisSample(s16* axis, int sampleIndex)
{
    return axis[sampleIndex + 1];
}

/*
 * Retail string evidence labels this source-side path as objanim.c/setBlendMove.
 */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void ObjAnim_SetBlendMove(ObjAnimComponent* objAnim, ObjAnimDef* animDef, ObjAnimState* state,
                          u32 moveId, int eventState)
{
    int requestedEventState;
    int moveIndex;
    ObjAnimMoveData* moveData;
    int blendFrameType;
    float blendFrameLength;

    requestedEventState = eventState;
    requestedEventState |= eventState;
    moveIndex = animDef->moveGroupBaseIndices[(s32)moveId >> OBJANIM_MOVE_GROUP_SHIFT] +
        (moveId & OBJANIM_MOVE_INDEX_MASK);
    if (moveIndex >= animDef->moveCount)
    {
        moveIndex = animDef->moveCount - 1;
    }
    if (moveIndex < 0)
    {
        moveIndex = 0;
    }
    if ((animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) != 0)
    {
        if (state->lastBlendMoveIndex != moveIndex)
        {
            state->blendCacheSlot = state->blendToggle;
            state->prevBlendCacheSlot = (u16)(OBJANIM_MOVE_CACHE_SLOT_COUNT - 1 - state->blendToggle);
            if (animDef->cachedAnimIds[moveIndex] == OBJANIM_MISSING_MOVE_ID)
            {
                OSReport(gObjAnimMissingCachedMoveWarning, animDef->modNo);
                moveIndex = 0;
            }
            ObjAnim_LoadCachedMove((int)animDef->cachedAnimIds[moveIndex], (int)(s16)moveIndex,
                                   state->blendMoveCache[state->blendCacheSlot], animDef);
            state->lastBlendMoveIndex = moveIndex;
        }
        moveData = (ObjAnimMoveData*)
            (state->blendMoveCache[state->blendCacheSlot] + OBJANIM_CACHED_MOVE_DATA_OFFSET);
    }
    else
    {
        state->blendCacheSlot = moveIndex;
        moveData = (ObjAnimMoveData*)animDef->moveData[state->blendCacheSlot];
    }
    state->blendFrameData = (ObjAnimFrameCommand*)moveData->frameCommands;
    blendFrameType = moveData->frameControl & OBJANIM_FRAME_TYPE_MASK;
    if (blendFrameType != state->frameType)
    {
        state->eventState = 0;
    }
    else
    {
        blendFrameLength = (float)state->blendFrameData->frameLength;
        if (blendFrameType == OBJANIM_FRAME_TYPE_CLAMPED)
        {
            blendFrameLength = blendFrameLength - gObjAnimProgressOne;
        }
        if (blendFrameLength != state->frameLength)
        {
            state->eventState = 0;
        }
        else
        {
            state->eventState = requestedEventState;
        }
    }
    return;
}
#pragma dont_inline reset

#pragma peephole on
void Object_ObjAnimSetPrimaryBlendMove(ObjAnimComponent* objAnim, u32 moveId, int eventState)
{
    ObjAnimBank* bank;

    bank = ObjAnim_GetActiveBank(objAnim);
    if (bank->animDef->moveCount != 0)
    {
        ObjAnim_SetBlendMove(objAnim, bank->animDef, bank->activeState, moveId, (s16)eventState);
    }
    return;
}

void Object_ObjAnimSetSecondaryBlendMove(ObjAnimComponent* objAnim, u32 moveId, int eventState)
{
    ObjAnimBank* bank;

    bank = ObjAnim_GetActiveBank(objAnim);
    if (bank->animDef->moveCount != 0)
    {
        ObjAnim_SetBlendMove(objAnim, bank->animDef, bank->currentState, moveId, (s16)eventState);
    }
    return;
}

#pragma peephole off
int Object_ObjAnimAdvanceMove(f32 moveStepScale, f32 deltaTime, int objAnimHandle,
                              ObjAnimEventList* events)
{
    ObjAnimComponent* objAnim;
    ObjAnimBank* bank;
    ObjAnimState* state;
    ObjAnimEventTable* eventTable;
    f32 previousProgress;
    f32 progressDelta;
    f32 prevFrameLength;
    f32 value;
    int wrapped;
    int countdown;
    int previousFrame;
    int currentFrame;
    int scanMode;
    int eventCount;
    int eventIndex;
    ObjAnimPackedEvent eventEntry;
    int eventFrame;
    int eventId;

    objAnim = (ObjAnimComponent*)objAnimHandle;
    wrapped = 0;
    bank = ObjAnim_GetActiveBank(objAnim);
    if (bank->animDef->moveCount == 0)
    {
        return 0;
    }

    state = bank->activeState;
    state->frameStep = moveStepScale * state->frameLength;
    if (state->eventCountdown != 0)
    {
        if ((state->moveControlFlags & OBJANIM_MOVE_CONTROL_REFRESH_SAVED_STEP) != 0)
        {
            state->savedFrameStep = state->frameStep;
        }
        state->prevFramePhase += state->savedFrameStep * deltaTime;
        prevFrameLength = state->prevFrameLength;
        if (state->prevFrameType != OBJANIM_FRAME_TYPE_CLAMPED)
        {
            if (state->prevFramePhase < gObjAnimProgressZero)
            {
                while (state->prevFramePhase < gObjAnimProgressZero)
                {
                    state->prevFramePhase += prevFrameLength;
                }
            }
            if (state->prevFramePhase >= prevFrameLength)
            {
                while (state->prevFramePhase >= prevFrameLength)
                {
                    state->prevFramePhase -= prevFrameLength;
                }
            }
        }
        else
        {
            state->prevFramePhase = (state->prevFramePhase < gObjAnimProgressZero)
                                        ? gObjAnimProgressZero
                                        : ((state->prevFramePhase > prevFrameLength)
                                               ? prevFrameLength
                                               : state->prevFramePhase);
        }

        if ((state->moveControlFlags & OBJANIM_MOVE_CONTROL_HOLD_EVENT_COUNTDOWN) == 0)
        {
            countdown =
                (int)
            ((f32)(s32)
            state->eventCountdown - ((f32)state->eventStep * deltaTime)
            )
            ;
            value = (countdown < 0)
                        ? gObjAnimProgressZero
                        : (((f32)countdown > gObjAnimEventStepScale)
                               ? gObjAnimEventStepScale
                               : (f32)countdown);
            state->eventCountdown = (u16)(int)
            value;
        }
        if (state->eventCountdown == 0)
        {
            state->prevEventState = 0;
        }
    }

    previousProgress = objAnim->activeMoveProgress;
    progressDelta = moveStepScale * deltaTime;
    objAnim->activeMoveProgress = previousProgress + progressDelta;
    if (objAnim->activeMoveProgress >= gObjAnimProgressOne)
    {
        if (state->frameType != OBJANIM_FRAME_TYPE_CLAMPED)
        {
            while (objAnim->activeMoveProgress >= gObjAnimProgressOne)
            {
                objAnim->activeMoveProgress -= gObjAnimProgressOne;
            }
        }
        else
        {
            objAnim->activeMoveProgress = gObjAnimProgressOne;
        }
        wrapped = 1;
    }
    else if (objAnim->activeMoveProgress < gObjAnimProgressZero)
    {
        if (state->frameType != OBJANIM_FRAME_TYPE_CLAMPED)
        {
            while (objAnim->activeMoveProgress < gObjAnimProgressZero)
            {
                objAnim->activeMoveProgress += gObjAnimProgressOne;
            }
        }
        else
        {
            objAnim->activeMoveProgress = gObjAnimProgressZero;
        }
        wrapped = 1;
    }

    if (events == NULL)
    {
        return wrapped;
    }

    events->rootCurveValid = 0;
    eventTable = objAnim->eventTable;
    if (eventTable != NULL)
    {
        events->triggerCount = 0;
        eventCount = objAnim->eventTable->byteCount >> 1;
        if (eventCount != 0)
        {
    previousFrame = (int)(gObjAnimEventFrameScale * previousProgress);
    currentFrame = (int)(gObjAnimEventFrameScale * objAnim->activeMoveProgress);
    scanMode = OBJANIM_EVENT_SCAN_FORWARD;
    if (currentFrame < previousFrame)
    {
        scanMode |= OBJANIM_EVENT_SCAN_WRAPPED;
    }
    if (progressDelta < gObjAnimProgressZero)
    {
        scanMode |= OBJANIM_EVENT_SCAN_REVERSE;
    }

    for (eventIndex = 0;
         eventIndex < eventCount && events->triggerCount < OBJANIM_EVENT_TRIGGER_CAPACITY;
         eventIndex++)
    {
        eventEntry = objAnim->eventTable->entries[eventIndex];
        eventFrame = ObjAnim_GetPackedEventFrame(eventEntry);
        eventId = ObjAnim_GetPackedEventId(eventEntry);
        if (eventId == OBJANIM_EVENT_ID_NONE)
        {
            continue;
        }

        if (scanMode == OBJANIM_EVENT_SCAN_FORWARD)
        {
            if ((eventFrame >= previousFrame) && (eventFrame < currentFrame))
            {
                events->triggeredIds[events->triggerCount++] = eventId;
            }
        }
        if (scanMode == OBJANIM_EVENT_SCAN_WRAPPED)
        {
            if ((eventFrame >= previousFrame) || (eventFrame < currentFrame))
            {
                events->triggeredIds[events->triggerCount++] = eventId;
            }
        }
        if (scanMode == OBJANIM_EVENT_SCAN_REVERSE_WRAPPED)
        {
            if ((eventFrame > currentFrame) && (eventFrame <= previousFrame))
            {
                events->triggeredIds[events->triggerCount++] = eventId;
            }
        }
        if (scanMode == OBJANIM_EVENT_SCAN_REVERSE)
        {
            if ((eventFrame > currentFrame) || (eventFrame <= previousFrame))
            {
                events->triggeredIds[events->triggerCount++] = eventId;
            }
        }
    }
        }
    }

    return wrapped;
}

#pragma scheduling on
#pragma peephole on
int Object_ObjAnimSetMoveProgress(f32 moveProgress, ObjAnimComponent* objAnim)
{
    if (moveProgress > gObjAnimSetMoveProgressMax)
    {
        moveProgress = gObjAnimSetMoveProgressMax;
    }
    else if (moveProgress < gObjAnimProgressZero)
    {
        moveProgress = gObjAnimProgressZero;
    }
    objAnim->activeMoveProgress = moveProgress;
    return 0;
}

int
#pragma scheduling off
#pragma peephole off
Object_ObjAnimSetMove(f32 moveProgress, int objAnimHandle, int moveId, int moveControlFlags)
{
    ObjAnimComponent* objAnim;
    ObjAnimBank* bank;
    ObjAnimDef* animDef;
    ObjAnimState* state;
    short previousMove;
    u8 moveChanged;
    int frameStep;
    ObjAnimMoveData* moveData;
    float eventCountdownStep;
    objAnim = (ObjAnimComponent*)objAnimHandle;
    if (moveProgress > gObjAnimProgressOne)
    {
        moveProgress = gObjAnimProgressOne;
    }
    else if (moveProgress < gObjAnimProgressZero)
    {
        moveProgress = gObjAnimProgressZero;
    }
    objAnim->activeMoveProgress = moveProgress;
    bank = ObjAnim_GetActiveBank(objAnim);
    animDef = bank->animDef;
    if (animDef->moveCount == 0)
    {
        return 0;
    }
    state = bank->activeState;
    state->moveControlFlags = moveControlFlags;
    state->prevMoveCacheSlot = state->moveCacheSlot;
    state->prevFramePhase = state->framePhase;
    state->prevFrameLength = state->frameLength;
    state->savedFrameStep = state->frameStep;
    state->prevMoveFrameData = state->moveFrameData;
    state->prevFrameType = state->frameType;
    state->prevBlendCacheSlot = state->blendCacheSlot;
    state->prevBlendFrameData = state->blendFrameData;
    state->prevEventState = state->eventState;
    state->eventState = 0;
    state->lastBlendMoveIndex = OBJANIM_BLEND_MOVE_INDEX_INVALID;
    previousMove = objAnim->activeMove;
    moveChanged = previousMove != moveId;
    objAnim->activeMove = moveId;
    moveId = ObjAnim_ResolveMoveIndex(animDef, moveId);
    if ((animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) != 0)
    {
        if (moveChanged != 0)
        {
            state->blendToggle = OBJANIM_MOVE_CACHE_SLOT_COUNT - 1 - state->blendToggle;
            state->moveCacheSlot = state->blendToggle;
            if (animDef->cachedAnimIds[moveId] == OBJANIM_MISSING_MOVE_ID)
            {
                OSReport(gObjAnimMissingCachedMoveWarning, animDef->modNo);
                moveId = 0;
            }
            ObjAnim_LoadCachedMove((int)animDef->cachedAnimIds[moveId], (int)(s16)moveId,
                                   state->moveCache[state->moveCacheSlot], animDef);
        }
        moveData =
            (ObjAnimMoveData*)(state->moveCache[state->moveCacheSlot] +
                OBJANIM_CACHED_MOVE_DATA_OFFSET);
    }
    else
    {
        state->moveCacheSlot = moveId;
        moveData = (ObjAnimMoveData*)animDef->moveData[state->moveCacheSlot];
    }
    state->moveFrameData = (ObjAnimFrameCommand*)moveData->frameCommands;
    state->frameType = moveData->frameControl & OBJANIM_FRAME_TYPE_MASK;
    state->frameLength = (float)state->moveFrameData->frameLength;
    if (state->frameType == OBJANIM_FRAME_TYPE_CLAMPED)
    {
        state->frameLength = state->frameLength - gObjAnimProgressOne;
    }
    frameStep = moveData->frameControl & OBJANIM_FRAME_STEP_MASK;
    if (frameStep != 0)
    {
        state->savedFrameStep = state->frameStep;
        eventCountdownStep = gObjAnimEventStepScale / (float)frameStep;
        state->eventStep = eventCountdownStep;
        state->eventCountdown = OBJANIM_EVENT_COUNTDOWN_RESET;
    }
    state->frameStep = gObjAnimProgressZero;
    state->framePhase = moveProgress * state->frameLength;
    return 0;
}

#pragma peephole on
u16 ObjAnim_GetCurrentEventCountdown(ObjAnimComponent* objAnim)
{
    return ObjAnim_GetCurrentState(objAnim)->eventCountdown;
}

void ObjAnim_WriteStateWord(ObjAnimComponent* objAnim, int stateIndex, short wordIndex, int value)
{
    ObjAnimBank* bank;
    ObjAnimState* state;
    u16* stateWords;
    u16 stateWord;

    bank = ObjAnim_GetActiveBank(objAnim);
    if (bank == NULL)
    {
        return;
    }
    stateWord = value;
    if (stateIndex != OBJANIM_STATE_INDEX_CURRENT)
    {
        state = bank->activeState;
    }
    else
    {
        state = bank->currentState;
    }
    stateWords = &state->eventCountdown;
    stateWords[wordIndex] = stateWord;
}

void ObjAnim_SetCurrentEventStepFrames(ObjAnimComponent* objAnim, u32 frameCount)
{
    ObjAnimBank* bank;
    float eventCountdownStep;

    bank = ObjAnim_GetActiveBank(objAnim);
    if (bank != NULL)
    {
        eventCountdownStep = gObjAnimEventStepScale / (float)(s32)frameCount;
        bank->currentState->eventStep = eventCountdownStep;
    }
}

#pragma peephole off
int ObjAnim_SampleRootCurvePhase(f32 distance, ObjAnimComponent* objAnim, float* phaseOut)
{
    ObjAnimBank* bank;
    ObjAnimDef* animDef;
    ObjAnimState* state;
    ObjAnimMoveData* moveData;
    ObjAnimRootCurve* curve;
    ObjAnimRootCurve* blendCurve;
    ObjModelInstance* model;
    s16* axis;
    s16* blendSamples;
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
    int hasFirstAxis;
    int broke;
    s16 axisFirstSample;

    bank = ObjAnim_GetActiveBank(objAnim);
    animDef = bank->animDef;
    if (animDef->moveCount == 0)
    {
        return 0;
    }

    state = bank->currentState;
    model = objAnim->modelInstance;
    targetDistance = distance * (objAnim->rootMotionScale / model->rootMotionScaleBase);
    blendSamples = NULL;

    if (state->eventState != 0)
    {
        blendWeight = state->eventState / gObjAnimEventStepScale;
        moveWeight = gObjAnimProgressOne - blendWeight;
        if ((animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) != 0)
        {
            moveData = (ObjAnimMoveData*)(state->blendMoveCache[state->blendCacheSlot] +
                OBJANIM_CACHED_MOVE_DATA_OFFSET);
        }
        else
        {
            moveData = (ObjAnimMoveData*)animDef->moveData[state->blendCacheSlot];
        }
        if (moveData->rootCurveOffset != 0)
        {
            blendCurve = ObjAnim_GetMoveDataRootCurve(moveData);
            blendScale = blendCurve->scale * objAnim->rootMotionScale;
            blendSamples = ObjAnim_GetRootCurveAxisData(blendCurve);
            if (*blendSamples == 0)
            {
                blendSamples++;
                if (*blendSamples == 0)
                {
                    blendSamples++;
                    if (*blendSamples == 0)
                    {
                        blendSamples = NULL;
                    }
                }
            }
            if (blendSamples != NULL)
            {
                blendSamples++;
            }
        }
    }

    if ((animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) != 0)
    {
        moveData = (ObjAnimMoveData*)(state->moveCache[state->moveCacheSlot] +
            OBJANIM_CACHED_MOVE_DATA_OFFSET);
    }
    else
    {
        moveData = (ObjAnimMoveData*)animDef->moveData[state->moveCacheSlot];
    }
    if (moveData->rootCurveOffset == 0)
    {
        goto noCurve;
    }
    curve = ObjAnim_GetMoveDataRootCurve(moveData);

    rootScale = curve->scale * objAnim->rootMotionScale;
    segmentCount = curve->sampleCount - 1;
    axis = ObjAnim_GetRootCurveAxisData(curve);
    hasFirstAxis = 0;
    axisFirstSample = *axis;
    if (axisFirstSample != 0)
    {
        hasFirstAxis = 1;
    }
    if (axisFirstSample == 0)
    {
        axis++;
    }
    if (hasFirstAxis == 0)
    {
        axisFirstSample = *axis;
        if (axisFirstSample == 0)
        {
            axis++;
        }
    }
    axisFirstSample = *axis;
    if (axisFirstSample == 0)
    {
        goto noCurve;
    }

    lastSample = ObjAnim_ReadRootAxisSample(axis, segmentCount);
    if (lastSample < 0)
    {
        rootScale = -rootScale;
    }
    if (lastSample == 0)
    {
        return 0;
    }

    sampleCount = segmentCount;
    phaseStep = gObjAnimProgressOne / sampleCount;
    sampleProgress = sampleCount * objAnim->currentMoveProgress;
    sampleIndex = sampleProgress;
    sampleFraction = sampleProgress - sampleIndex;

    if (blendSamples != NULL)
    {
        s16* axisAt;
        if (blendSamples[segmentCount] < 0)
        {
            blendScale = -blendScale;
        }
        axisAt = &axis[sampleIndex];
        previousDistance = rootScale * (moveWeight * axisAt[1]);
        previousDistance += blendScale * (blendWeight * blendSamples[sampleIndex]);
        nextDistance = rootScale * (moveWeight * axisAt[2]);
        nextDistance += blendScale * (blendWeight * blendSamples[sampleIndex + 1]);
    }
    else
    {
        s16* axisAt = &axis[sampleIndex];
        previousDistance = rootScale * axisAt[1];
        nextDistance = rootScale * axisAt[2];
    }

    targetDistance += previousDistance + sampleFraction * (nextDistance - previousDistance);
    phase = phaseStep - (phaseStep * sampleFraction);
    broke = 0;
    do
    {
        if (nextDistance > targetDistance)
        {
            phase -= (phaseStep * (nextDistance - targetDistance)) /
                (nextDistance - previousDistance);
            broke = 1;
        }
        else
        {
            sampleIndex++;
            if (sampleIndex >= segmentCount)
            {
                sampleIndex = 0;
            }
            previousDistance = nextDistance;
            if (blendSamples != NULL)
            {
                s16* axisAt = &axis[sampleIndex];
                nextDistance +=
                    (rootScale * ((f32)axisAt[2] - axisAt[1]) * moveWeight) +
                    (blendScale * ((f32)blendSamples[sampleIndex + 1] - blendSamples[sampleIndex]) * blendWeight);
            }
            else
            {
                s16* axisAt = &axis[sampleIndex];
                nextDistance +=
                    rootScale * ((f32)axisAt[2] - axisAt[1]);
            }
            phase += phaseStep;
        }
    } while (!broke);

    if (phaseOut != NULL)
    {
        *phaseOut = phase;
    }
    return 1;

noCurve:
    return 0;
}

int ObjAnim_AdvanceCurrentMove(f32 moveStepScale, f32 deltaTime, int objAnimHandle,
                               ObjAnimEventList* events)
{
    ObjAnimComponent* objAnim;
    ObjAnimBank* bank;
    ObjAnimState* state;
    ObjAnimEventTable* eventTable;
    ObjAnimMoveData* moveData;
    ObjAnimRootCurve* curve;
    ObjAnimRootCurve* blendCurve;
    s16* axis;
    s16* blendAxis;
    f32 previousProgress;
    f32 progressDelta;
    f32 clampedStepScale;
    f32 prevFrameLength;
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
    int segmentCount;
    int previousSampleIndex;
    int currentSampleIndex;
    ObjAnimPackedEvent eventEntry;
    int eventFrame;
    int eventId;

    objAnim = (ObjAnimComponent*)objAnimHandle;
    wrapped = 0;
    clampedStepScale = (moveStepScale < gObjAnimMoveStepScaleMin)
                           ? gObjAnimMoveStepScaleMin
                           : ((moveStepScale > gObjAnimProgressOne) ? gObjAnimProgressOne
                                                                    : moveStepScale);

    bank = objAnim->banks[objAnim->bankIndex];
    if (bank->animDef->moveCount == 0)
    {
        return 0;
    }

    state = bank->currentState;
    if (state == NULL)
    {
        return 0;
    }

    state->frameStep = clampedStepScale * state->frameLength;
    if (state->eventCountdown != 0)
    {
        if ((state->moveControlFlags & OBJANIM_MOVE_CONTROL_REFRESH_SAVED_STEP) != 0)
        {
            state->savedFrameStep = state->frameStep;
        }
        state->prevFramePhase += state->savedFrameStep * deltaTime;
        prevFrameLength = state->prevFrameLength;
        if (state->prevFrameType != OBJANIM_FRAME_TYPE_CLAMPED)
        {
            if (state->prevFramePhase < gObjAnimProgressZero)
            {
                while (state->prevFramePhase < gObjAnimProgressZero)
                {
                    state->prevFramePhase += prevFrameLength;
                }
            }
            if (state->prevFramePhase >= prevFrameLength)
            {
                while (state->prevFramePhase >= prevFrameLength)
                {
                    state->prevFramePhase -= prevFrameLength;
                }
            }
        }
        else
        {
            state->prevFramePhase = (state->prevFramePhase < gObjAnimProgressZero)
                                        ? gObjAnimProgressZero
                                        : ((state->prevFramePhase > prevFrameLength)
                                               ? prevFrameLength
                                               : state->prevFramePhase);
        }

        if ((state->moveControlFlags & OBJANIM_MOVE_CONTROL_HOLD_EVENT_COUNTDOWN) == 0)
        {
            countdown = (int)
            ((f32)(s32)
            state->eventCountdown - ((f32)state->eventStep * deltaTime)
            )
            ;
            value = (countdown < 0)
                        ? gObjAnimProgressZero
                        : (((f32)countdown > gObjAnimEventStepScale)
                               ? gObjAnimEventStepScale
                               : (f32)countdown);
            state->eventCountdown = (u16)(int)
            value;
        }
        if (state->eventCountdown == 0)
        {
            state->prevEventState = 0;
        }
    }

    previousProgress = objAnim->currentMoveProgress;
    progressDelta = clampedStepScale * deltaTime;
    objAnim->currentMoveProgress = previousProgress + progressDelta;
    if (objAnim->currentMoveProgress >= gObjAnimProgressOne)
    {
        if (state->frameType != OBJANIM_FRAME_TYPE_CLAMPED)
        {
            while (objAnim->currentMoveProgress >= gObjAnimProgressOne)
            {
                objAnim->currentMoveProgress -= gObjAnimProgressOne;
            }
        }
        else
        {
            objAnim->currentMoveProgress = gObjAnimProgressOne;
        }
        wrapped = 1;
    }
    else if (objAnim->currentMoveProgress < gObjAnimProgressZero)
    {
        if (state->frameType != OBJANIM_FRAME_TYPE_CLAMPED)
        {
            while (objAnim->currentMoveProgress < gObjAnimProgressZero)
            {
                objAnim->currentMoveProgress += gObjAnimProgressOne;
            }
        }
        else
        {
            objAnim->currentMoveProgress = gObjAnimProgressZero;
        }
        wrapped = 1;
    }

    if (events == NULL)
    {
        return wrapped;
    }

    events->rootCurveValid = 0;
    events->rootDeltaZ = gObjAnimProgressZero;
    events->rootDeltaY = gObjAnimProgressZero;
    events->rootDeltaX = gObjAnimProgressZero;
    eventTable = objAnim->eventTable;
    if (eventTable != NULL)
    {
        events->triggerCount = 0;
        eventCount = objAnim->eventTable->byteCount >> 1;
        if (eventCount != 0)
        {
            previousFrame = (int)(gObjAnimEventFrameScale * previousProgress);
            currentFrame = (int)(gObjAnimEventFrameScale * objAnim->currentMoveProgress);
            scanMode = OBJANIM_EVENT_SCAN_FORWARD;
            if (currentFrame < previousFrame)
            {
                scanMode |= OBJANIM_EVENT_SCAN_WRAPPED;
            }
            if (progressDelta < gObjAnimProgressZero)
            {
                scanMode |= OBJANIM_EVENT_SCAN_REVERSE;
            }

            for (eventIndex = 0;
                 eventIndex < eventCount && events->triggerCount < OBJANIM_EVENT_TRIGGER_CAPACITY;
                 eventIndex++)
            {
                eventEntry = objAnim->eventTable->entries[eventIndex];
                eventFrame = ObjAnim_GetPackedEventFrame(eventEntry);
                eventId = ObjAnim_GetPackedEventId(eventEntry);
                if (eventId == OBJANIM_EVENT_ID_NONE)
                {
                    continue;
                }

                if (scanMode == OBJANIM_EVENT_SCAN_FORWARD)
                {
                    if ((eventFrame >= previousFrame) && (eventFrame < currentFrame))
                    {
                        events->triggeredIds[events->triggerCount++] = eventId;
                    }
                }
                if (scanMode == OBJANIM_EVENT_SCAN_WRAPPED)
                {
                    if ((eventFrame >= previousFrame) || (eventFrame < currentFrame))
                    {
                        events->triggeredIds[events->triggerCount++] = eventId;
                    }
                }
                if (scanMode == OBJANIM_EVENT_SCAN_REVERSE_WRAPPED)
                {
                    if ((eventFrame > currentFrame) && (eventFrame <= previousFrame))
                    {
                        events->triggeredIds[events->triggerCount++] = eventId;
                    }
                }
                if (scanMode == OBJANIM_EVENT_SCAN_REVERSE)
                {
                    if ((eventFrame > currentFrame) || (eventFrame <= previousFrame))
                    {
                        events->triggeredIds[events->triggerCount++] = eventId;
                    }
                }
            }
        }
    }

    if ((bank->animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) != 0)
    {
        moveData = (ObjAnimMoveData*)(state->moveCache[state->moveCacheSlot] +
            OBJANIM_CACHED_MOVE_DATA_OFFSET);
    }
    else
    {
        moveData = (ObjAnimMoveData*)bank->animDef->moveData[state->moveCacheSlot];
    }
    if (moveData->rootCurveOffset != 0)
    {
    events->rootCurveValid = 1;
    curve = ObjAnim_GetMoveDataRootCurve(moveData);
    rootScale = curve->scale * objAnim->rootMotionScale;
    segmentCount = curve->sampleCount - 1;
    axis = ObjAnim_GetRootCurveAxisData(curve);
    previousScaledSample = segmentCount * previousProgress;
    previousSampleIndex = previousScaledSample;
    previousFraction = previousScaledSample - previousSampleIndex;
    currentScaledSample = segmentCount * objAnim->currentMoveProgress;
    currentSampleIndex = currentScaledSample;
    currentFraction = currentScaledSample - currentSampleIndex;

    blendAxis = NULL;
    if (state->eventState != 0)
    {
        blendWeight = state->eventState / gObjAnimEventStepScale;
        moveWeight = gObjAnimProgressOne - blendWeight;
        if ((bank->animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) != 0)
        {
            moveData = (ObjAnimMoveData*)(state->blendMoveCache[state->blendCacheSlot] +
                OBJANIM_CACHED_MOVE_DATA_OFFSET);
        }
        else
        {
            moveData = (ObjAnimMoveData*)bank->animDef->moveData[state->blendCacheSlot];
        }
        blendCurve = ObjAnim_GetMoveDataRootCurve(moveData);
        blendAxis = ObjAnim_GetRootCurveAxisData(blendCurve);
    }
    else
    {
        blendWeight = gObjAnimProgressZero;
        moveWeight = gObjAnimProgressOne;
    }

    axisIndex = 0;
    do
    {
        if (*axis == 0)
        {
            axis++;
            if (blendAxis != NULL)
            {
                blendAxis++;
            }
            if (axisIndex < OBJANIM_ROOT_CURVE_TRANSLATION_AXIS_COUNT)
            {
                (&events->rootDeltaX)[axisIndex] = gObjAnimProgressZero;
            }
            else
            {
                (&events->rootYaw)[axisIndex - OBJANIM_ROOT_CURVE_TRANSLATION_AXIS_COUNT] = 0;
            }
        }
        else
        {
            axis++;
            if (blendAxis != NULL)
            {
                blendAxis++;
            }
            previousAxisValue = moveWeight * axis[previousSampleIndex];
            if (blendAxis != NULL)
            {
                previousAxisValue += blendWeight * blendAxis[previousSampleIndex];
            }
            previousAxisNextValue = moveWeight * axis[previousSampleIndex + 1];
            if (blendAxis != NULL)
            {
                previousAxisNextValue += blendWeight * blendAxis[previousSampleIndex + 1];
            }
            previousInterp = previousAxisValue +
                previousFraction * (previousAxisNextValue - previousAxisValue);

            currentAxisValue = moveWeight * axis[currentSampleIndex];
            if (blendAxis != NULL)
            {
                currentAxisValue += blendWeight * blendAxis[currentSampleIndex];
            }
            currentAxisNextValue = moveWeight * axis[currentSampleIndex + 1];
            if (blendAxis != NULL)
            {
                currentAxisNextValue += blendWeight * blendAxis[currentSampleIndex + 1];
            }
            currentInterp = currentAxisValue +
                currentFraction * (currentAxisNextValue - currentAxisValue);

            if (progressDelta > gObjAnimProgressZero)
            {
                if (objAnim->currentMoveProgress < previousProgress)
                {
                    currentInterp += moveWeight * axis[segmentCount];
                    if (blendAxis != NULL)
                    {
                        currentInterp += blendWeight * blendAxis[segmentCount];
                    }
                }
                value = currentInterp - previousInterp;
            }
            else
            {
                if (objAnim->currentMoveProgress > previousProgress)
                {
                    currentInterp -= moveWeight * axis[segmentCount];
                    if (blendAxis != NULL)
                    {
                        currentInterp += blendWeight * blendAxis[segmentCount];
                    }
                }
                value = currentInterp - previousInterp;
            }

            if (axisIndex < OBJANIM_ROOT_CURVE_TRANSLATION_AXIS_COUNT)
            {
                (&events->rootDeltaX)[axisIndex] = value * rootScale;
            }
            else
            {
                (&events->rootYaw)[axisIndex - OBJANIM_ROOT_CURVE_TRANSLATION_AXIS_COUNT] =
                    value;
            }

            axis += segmentCount + 1;
            if (blendAxis != NULL)
            {
                blendAxis += segmentCount + 1;
            }
        }
        axisIndex++;
    } while (axisIndex < OBJANIM_ROOT_CURVE_AXIS_COUNT);
    }
    else
    {
        events->rootCurveValid = 0;
    }
    return wrapped;
}

#pragma scheduling on
#pragma peephole on
int ObjAnim_SetMoveProgress(f32 moveProgress, ObjAnimComponent* objAnim)
{
    if (moveProgress > gObjAnimSetMoveProgressMax)
    {
        moveProgress = gObjAnimSetMoveProgressMax;
    }
    else if (moveProgress < gObjAnimProgressZero)
    {
        moveProgress = gObjAnimProgressZero;
    }
    objAnim->currentMoveProgress = moveProgress;
    return 0;
}

#pragma scheduling off
#pragma peephole off
int ObjAnim_SetCurrentMove(int objAnimHandle, int moveId, f32 moveProgress, int moveControlFlags)
{
    ObjAnimComponent* objAnim;
    ObjAnimBank* bank;
    ObjAnimDef* animDef;
    ObjAnimState* state;
    s16 previousMove;
    u8 moveChanged;
    int requestedMoveId;
    int frameStep;
    ObjAnimMoveData* moveData;
    float eventCountdownStep;
    ObjHitReactState* hitState;

    objAnim = (ObjAnimComponent*)objAnimHandle;
    requestedMoveId = moveId;
    if (moveProgress > gObjAnimProgressOne)
    {
        moveProgress = gObjAnimProgressOne;
    }
    else if (moveProgress < gObjAnimProgressZero)
    {
        moveProgress = gObjAnimProgressZero;
    }
    objAnim->currentMoveProgress = moveProgress;
    bank = ObjAnim_GetActiveBank(objAnim);
    if (bank == NULL)
    {
        return 0;
    }
    animDef = bank->animDef;
    if (animDef->moveCount == 0)
    {
        return 0;
    }
    state = bank->currentState;
    state->moveControlFlags = moveControlFlags;
    state->prevMoveCacheSlot = state->moveCacheSlot;
    state->prevFramePhase = state->framePhase;
    state->prevFrameLength = state->frameLength;
    state->savedFrameStep = state->frameStep;
    state->prevMoveFrameData = state->moveFrameData;
    state->prevFrameType = state->frameType;
    state->prevBlendCacheSlot = state->blendCacheSlot;
    state->prevBlendFrameData = state->blendFrameData;
    state->prevEventState = state->eventState;
    state->eventState = 0;
    state->lastBlendMoveIndex = OBJANIM_BLEND_MOVE_INDEX_INVALID;
    hitState = objAnim->hitReactState;
    if ((hitState != NULL) && (hitState->entries != NULL))
    {
        ObjHitReact_LoadMoveEntries((ObjAnimComponent*)objAnimHandle, bank, objAnim->seqId,
                                    hitState, requestedMoveId, 0);
    }
    if (objAnim->eventTable != NULL)
    {
        ObjAnim_LoadMoveEvents((u8*)objAnimHandle, objAnim->seqId, objAnim->eventTable,
                               requestedMoveId, 0);
    }
    previousMove = objAnim->currentMove;
    moveChanged = previousMove != requestedMoveId;
    objAnim->currentMove = requestedMoveId;
    moveId = animDef->moveGroupBaseIndices[requestedMoveId >> OBJANIM_MOVE_GROUP_SHIFT] +
        (requestedMoveId & OBJANIM_MOVE_INDEX_MASK);
    if (moveId >= animDef->moveCount)
    {
        moveId = animDef->moveCount - 1;
    }
    if (moveId < 0)
    {
        moveId = 0;
    }
    if ((animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) != 0)
    {
        if (moveChanged != 0)
        {
            state->blendToggle = OBJANIM_MOVE_CACHE_SLOT_COUNT - 1 - state->blendToggle;
            state->moveCacheSlot = state->blendToggle;
            if (animDef->cachedAnimIds[moveId] == OBJANIM_MISSING_MOVE_ID)
            {
                OSReport(gObjAnimMissingCachedMoveWarning, animDef->modNo);
                moveId = 0;
            }
            ObjAnim_LoadCachedMove((int)animDef->cachedAnimIds[moveId], (int)(s16)moveId,
                                   state->moveCache[state->moveCacheSlot], animDef);
        }
        moveData =
            (ObjAnimMoveData*)(state->moveCache[state->moveCacheSlot] +
                OBJANIM_CACHED_MOVE_DATA_OFFSET);
    }
    else
    {
        state->moveCacheSlot = moveId;
        moveData = (ObjAnimMoveData*)animDef->moveData[state->moveCacheSlot];
    }
    state->moveFrameData = (ObjAnimFrameCommand*)moveData->frameCommands;
    state->frameType = moveData->frameControl & OBJANIM_FRAME_TYPE_MASK;
    state->frameLength = (float)state->moveFrameData->frameLength;
    if (state->frameType == OBJANIM_FRAME_TYPE_CLAMPED)
    {
        state->frameLength = state->frameLength - gObjAnimProgressOne;
    }
    frameStep = moveData->frameControl & OBJANIM_FRAME_STEP_MASK;
    if ((frameStep != 0) &&
        (((u8)moveControlFlags & OBJANIM_MOVE_CONTROL_SKIP_EVENT_COUNTDOWN) == 0))
    {
        state->savedFrameStep = state->frameStep;
        eventCountdownStep = gObjAnimEventStepScale / (float)frameStep;
        state->eventStep = eventCountdownStep;
        state->eventCountdown = OBJANIM_EVENT_COUNTDOWN_RESET;
    }
    else
    {
        state->eventCountdown = 0;
    }
    state->frameStep = gObjAnimProgressZero;
    state->framePhase = moveProgress * state->frameLength;
    return 0;
}
