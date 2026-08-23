#include "dolphin/os.h"
#include "main/objHitReact.h"
#include "main/objanim_internal.h"
#include "main/objhits.h"
#include "main/objanim.h"

/*
 * Retail string evidence labels this source-side path as objanim.c/setBlendMove.
 */
const f32 gObjAnimProgressOne[1] = {1.0f};

#define OBJANIM_PROGRESS_ONE (gObjAnimProgressOne[0])

void ObjAnim_SetBlendMove(ObjAnimComponent* objAnim, ObjAnimDef* animDef, ObjAnimState* state, u32 moveId,
                          int eventState)
{
    int requestedEventState;
    int moveIndex;
    ObjAnimMoveData* moveData;
    int blendFrameType;
    float blendFrameLength;

    requestedEventState = eventState;
    requestedEventState |= eventState;
    moveIndex =
        animDef->moveGroupBaseIndices[(s32)moveId >> OBJANIM_MOVE_GROUP_SHIFT] + (moveId & OBJANIM_MOVE_INDEX_MASK);
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
        moveData = (ObjAnimMoveData*)(state->blendMoveCache[state->blendCacheSlot] + OBJANIM_CACHED_MOVE_DATA_OFFSET);
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
            blendFrameLength = blendFrameLength - OBJANIM_PROGRESS_ONE;
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

int Object_ObjAnimAdvanceMove(void* objAnimHandle, f32 moveStepScale, f32 deltaTime, ObjAnimEventList* events)
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
    int eventCount;
    int eventIndex;
    ObjAnimPackedEvent eventEntry;
    int previousFrame;
    int currentFrame;
    int eventId;
    int eventFrame;
    int scanMode;

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
            if (state->prevFramePhase < 0.0f)
            {
                while (state->prevFramePhase < 0.0f)
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
            state->prevFramePhase =
                (state->prevFramePhase < 0.0f)
                    ? 0.0f
                    : ((state->prevFramePhase > prevFrameLength) ? prevFrameLength : state->prevFramePhase);
        }

        if ((state->moveControlFlags & OBJANIM_MOVE_CONTROL_HOLD_EVENT_COUNTDOWN) == 0)
        {
            countdown = (int)((f32)(s32)state->eventCountdown - ((f32)state->eventStep * deltaTime));
            value = (countdown < 0)
                        ? 0.0f
                        : (((f32)countdown > 16384.0f) ? 16384.0f : (f32)countdown);
            state->eventCountdown = (u16)(int)value;
        }
        if (state->eventCountdown == 0)
        {
            state->prevEventState = 0;
        }
    }

    previousProgress = objAnim->activeMoveProgress;
    progressDelta = moveStepScale * deltaTime;
    objAnim->activeMoveProgress = previousProgress + progressDelta;
    if (objAnim->activeMoveProgress >= OBJANIM_PROGRESS_ONE)
    {
        if (state->frameType != OBJANIM_FRAME_TYPE_CLAMPED)
        {
            while (objAnim->activeMoveProgress >= OBJANIM_PROGRESS_ONE)
            {
                objAnim->activeMoveProgress -= OBJANIM_PROGRESS_ONE;
            }
        }
        else
        {
            objAnim->activeMoveProgress = OBJANIM_PROGRESS_ONE;
        }
        wrapped = 1;
    }
    else if (objAnim->activeMoveProgress < 0.0f)
    {
        if (state->frameType != OBJANIM_FRAME_TYPE_CLAMPED)
        {
            while (objAnim->activeMoveProgress < 0.0f)
            {
                objAnim->activeMoveProgress += OBJANIM_PROGRESS_ONE;
            }
        }
        else
        {
            objAnim->activeMoveProgress = 0.0f;
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
            previousFrame = (int)(512.0f * previousProgress);
            currentFrame = (int)(512.0f * objAnim->activeMoveProgress);
            scanMode = OBJANIM_EVENT_SCAN_FORWARD;
            if (currentFrame < previousFrame)
            {
                scanMode |= OBJANIM_EVENT_SCAN_WRAPPED;
            }
            if (progressDelta < 0.0f)
            {
                scanMode |= OBJANIM_EVENT_SCAN_REVERSE;
            }

            for (eventIndex = 0; eventIndex < eventCount && events->triggerCount < OBJANIM_EVENT_TRIGGER_CAPACITY;
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

const f32 gObjAnimSetMoveProgressMax[1] = {0.999f};

#define OBJANIM_SET_MOVE_PROGRESS_MAX (gObjAnimSetMoveProgressMax[0])

int Object_ObjAnimSetMoveProgress(ObjAnimComponent* objAnim, f32 moveProgress)
{
    if (moveProgress > OBJANIM_SET_MOVE_PROGRESS_MAX)
    {
        moveProgress = OBJANIM_SET_MOVE_PROGRESS_MAX;
    }
    else if (moveProgress < 0.0f)
    {
        moveProgress = 0.0f;
    }
    objAnim->activeMoveProgress = moveProgress;
    return 0;
}

int
Object_ObjAnimSetMove(void* objAnimHandle, int moveId, f32 moveProgress, u8 moveControlFlags)
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
    if (moveProgress > OBJANIM_PROGRESS_ONE)
    {
        moveProgress = OBJANIM_PROGRESS_ONE;
    }
    else if (moveProgress < 0.0f)
    {
        moveProgress = 0.0f;
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
        moveData = (ObjAnimMoveData*)(state->moveCache[state->moveCacheSlot] + OBJANIM_CACHED_MOVE_DATA_OFFSET);
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
        state->frameLength = state->frameLength - OBJANIM_PROGRESS_ONE;
    }
    frameStep = moveData->frameControl & OBJANIM_FRAME_STEP_MASK;
    if (frameStep != 0)
    {
        state->savedFrameStep = state->frameStep;
        eventCountdownStep = 16384.0f / (float)frameStep;
        state->eventStep = eventCountdownStep;
        state->eventCountdown = OBJANIM_EVENT_COUNTDOWN_RESET;
    }
    state->frameStep = 0.0f;
    state->framePhase = moveProgress * state->frameLength;
    return 0;
}

int ObjAnim_GetCurrentEventCountdown(ObjAnimComponent* objAnim)
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
        eventCountdownStep = 16384.0f / (float)(s32)frameCount;
        bank->currentState->eventStep = eventCountdownStep;
    }
}

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
    return ObjAnim_ReadPackedS16(&axis[sampleIndex + 1]);
}

int ObjAnim_SampleRootCurvePhase(ObjAnimComponent* objAnim, f32 distance, float* phaseOut)
{
    s16* axisSamples;
    f32 blendDistanceDelta;
    f32 moveDistanceDelta;
    ObjAnimBank* bank;
    ObjAnimRootCurve* moveCurve;
    f32 segmentStartDistance;
    ObjAnimMoveData* moveData;
    ObjAnimState* state;
    ObjAnimRootCurve* blendCurve;
    ObjModelInstance* model;
    s16* moveSamples;
    s16* blendSamples;
    s16 axisMarker;
    f32 segmentEndDistance;
    int sampleIndex;
    f32 targetTravelDistance;
    f32 curveProgress;
    f32 phase;
    int lastSample;
    f32 phaseStep;
    f32 curveFraction;
    f32 moveRootScale;
    int segmentCount;
    int segmentOffset;
    f32 sampleCount;
    f32 blendScale;
    f32 blendWeight;
    f32 moveWeight;
    f32 rootMotionScale;
    int hasFirstAxis;
    int foundPhase;
    ObjAnimDef* animDef;

    bank = ObjAnim_GetActiveBank(objAnim);
    animDef = bank->animDef;
    if (animDef->moveCount == 0)
    {
        return 0;
    }

    state = bank->currentState;
    rootMotionScale = objAnim->rootMotionScale;
    model = objAnim->modelInstance;
    targetTravelDistance = distance * (rootMotionScale / model->rootMotionScaleBase);
    blendSamples = NULL;

    if (state->eventState != 0)
    {
        blendWeight = state->eventState / 16384.0f;
        moveWeight = OBJANIM_PROGRESS_ONE - blendWeight;
        if ((animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) != 0)
        {
            moveData =
                (ObjAnimMoveData*)(state->blendMoveCache[state->blendCacheSlot] + OBJANIM_CACHED_MOVE_DATA_OFFSET);
        }
        else
        {
            moveData = (ObjAnimMoveData*)animDef->moveData[state->blendCacheSlot];
        }
        if (moveData->rootCurveOffset != 0)
        {
            blendCurve = ObjAnim_GetMoveDataRootCurve(moveData);
            blendScale = blendCurve->scale * rootMotionScale;
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
        moveData = (ObjAnimMoveData*)(state->moveCache[state->moveCacheSlot] + OBJANIM_CACHED_MOVE_DATA_OFFSET);
    }
    else
    {
        moveData = (ObjAnimMoveData*)animDef->moveData[state->moveCacheSlot];
    }
    if (moveData->rootCurveOffset != 0)
    {
        moveCurve = ObjAnim_GetMoveDataRootCurve(moveData);

        moveRootScale = moveCurve->scale * rootMotionScale;
        segmentCount = moveCurve->sampleCount - 1;
        moveSamples = ObjAnim_GetRootCurveAxisData(moveCurve);
        hasFirstAxis = 0;
        axisMarker = *moveSamples;
        if (axisMarker != 0)
        {
            hasFirstAxis = 1;
        }
        if (axisMarker == 0)
        {
            moveSamples++;
        }
        if (hasFirstAxis == 0)
        {
            axisMarker = *moveSamples;
            if (axisMarker == 0)
            {
                moveSamples++;
            }
        }
        axisMarker = *moveSamples;
        if (axisMarker != 0)
        {
            moveSamples++;
            segmentOffset = segmentCount * 2;
            lastSample = moveSamples[segmentCount];
            if (lastSample < 0)
            {
                moveRootScale = -moveRootScale;
            }
            if (lastSample == 0)
            {
                return 0;
            }

            sampleCount = segmentCount;
            phaseStep = OBJANIM_PROGRESS_ONE / sampleCount;
            curveProgress = sampleCount * objAnim->currentMoveProgress;
            sampleIndex = curveProgress;
            curveFraction = curveProgress - sampleIndex;

            if (blendSamples != NULL)
            {
                if (*(s16*)((u8*)blendSamples + segmentOffset) < 0)
                {
                    blendScale = -blendScale;
                }
                segmentStartDistance = moveRootScale * (moveWeight * moveSamples[sampleIndex]);
                segmentStartDistance += blendScale * (blendWeight * blendSamples[sampleIndex]);
                segmentEndDistance = moveRootScale * (moveWeight * moveSamples[sampleIndex + 1]);
                segmentEndDistance += blendScale * (blendWeight * blendSamples[sampleIndex + 1]);
            }
            else
            {
                segmentStartDistance = moveRootScale * moveSamples[sampleIndex];
                segmentEndDistance = moveRootScale * moveSamples[sampleIndex + 1];
            }

            targetTravelDistance += segmentStartDistance + curveFraction * (segmentEndDistance - segmentStartDistance);
            phase = phaseStep - (phaseStep * curveFraction);
            foundPhase = 0;
            do
            {
                if (segmentEndDistance > targetTravelDistance)
                {
                    phase -=
                        (phaseStep * (segmentEndDistance - targetTravelDistance)) /
                        (segmentEndDistance - segmentStartDistance);
                    foundPhase = 1;
                }
                else
                {
                    sampleIndex++;
                    if (sampleIndex >= segmentCount)
                    {
                        sampleIndex = 0;
                    }
                    segmentStartDistance = segmentEndDistance;
                    if (blendSamples != NULL)
                    {
                        axisSamples = &moveSamples[sampleIndex];
                        moveDistanceDelta = moveRootScale * ((f32)axisSamples[1] - axisSamples[0]);
                        axisSamples = &blendSamples[sampleIndex];
                        blendDistanceDelta = blendScale * ((f32)axisSamples[1] - axisSamples[0]);
                        segmentEndDistance += (moveDistanceDelta * moveWeight) + (blendDistanceDelta * blendWeight);
                    }
                    else
                    {
                        axisSamples = &moveSamples[sampleIndex];
                        segmentEndDistance += moveRootScale * ((f32)axisSamples[1] - axisSamples[0]);
                    }
                    phase += phaseStep;
                }
            } while (!foundPhase);

            if (phaseOut != NULL)
            {
                *phaseOut = phase;
            }
            return 1;
        }
    }
    return 0;
}

const f32 gObjAnimMoveStepScaleMin[1] = {-1.0f};

#define OBJANIM_MOVE_STEP_SCALE_MIN (gObjAnimMoveStepScaleMin[0])

int ObjAnim_AdvanceCurrentMove(void* objAnimHandle, f32 moveStepScale, f32 deltaTime, ObjAnimEventList* events)
{
    int segmentCount;
    ObjAnimComponent* objAnim;
    ObjAnimBank* bank;
    ObjAnimEventTable* eventTable;
    ObjAnimMoveData* moveData;
    ObjAnimRootCurve* blendCurve;
    f32 clampedStepScale;
    f32 prevFrameLength;
    f32 value;
    f32 previousAxisValue;
    f32 previousAxisNextValue;
    f32 currentAxisValue;
    f32 currentAxisNextValue;
    f32 previousFraction;
    f32 currentInterp;
    f32 progressDelta;
    f32 previousScaledSample;
    f32 currentScaledSample;
    f32 previousProgress;
    f32 currentFraction;
    f32 previousInterp;
    f32 rootScale;
    f32 blendWeight;
    f32 moveWeight;
    f32 sampleSpan;
    int countdown;
    int eventId;
    int eventCount;
    ObjAnimState* state;
    int eventIndex;
    int previousFrame;
    int wrapped;
    int currentFrame;
    int axisIndex;
    s16* axis;
    s16* blendAxis;
    s16* at;
    int previousSampleIndex;
    int currentSampleIndex;
    int eventFrame;
    int scanMode;

    objAnim = (ObjAnimComponent*)objAnimHandle;
    wrapped = 0;
    clampedStepScale = (moveStepScale < OBJANIM_MOVE_STEP_SCALE_MIN)
                           ? OBJANIM_MOVE_STEP_SCALE_MIN
                           : ((moveStepScale > OBJANIM_PROGRESS_ONE) ? OBJANIM_PROGRESS_ONE : moveStepScale);

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
            if (state->prevFramePhase < 0.0f)
            {
                while (state->prevFramePhase < 0.0f)
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
            state->prevFramePhase =
                (state->prevFramePhase < 0.0f)
                    ? 0.0f
                    : ((state->prevFramePhase > prevFrameLength) ? prevFrameLength : state->prevFramePhase);
        }

        if ((state->moveControlFlags & OBJANIM_MOVE_CONTROL_HOLD_EVENT_COUNTDOWN) == 0)
        {
            countdown = (int)((f32)(s32)state->eventCountdown - ((f32)state->eventStep * deltaTime));
            value = (countdown < 0)
                        ? 0.0f
                        : (((f32)countdown > 16384.0f) ? 16384.0f : (f32)countdown);
            state->eventCountdown = (u16)(int)value;
        }
        if (state->eventCountdown == 0)
        {
            state->prevEventState = 0;
        }
    }

    previousProgress = objAnim->currentMoveProgress;
    progressDelta = clampedStepScale * deltaTime;
    objAnim->currentMoveProgress = previousProgress + progressDelta;
    if (objAnim->currentMoveProgress >= OBJANIM_PROGRESS_ONE)
    {
        if (state->frameType != OBJANIM_FRAME_TYPE_CLAMPED)
        {
            while (objAnim->currentMoveProgress >= OBJANIM_PROGRESS_ONE)
            {
                objAnim->currentMoveProgress -= OBJANIM_PROGRESS_ONE;
            }
        }
        else
        {
            objAnim->currentMoveProgress = OBJANIM_PROGRESS_ONE;
        }
        wrapped = 1;
    }
    else if (objAnim->currentMoveProgress < 0.0f)
    {
        if (state->frameType != OBJANIM_FRAME_TYPE_CLAMPED)
        {
            while (objAnim->currentMoveProgress < 0.0f)
            {
                objAnim->currentMoveProgress += OBJANIM_PROGRESS_ONE;
            }
        }
        else
        {
            objAnim->currentMoveProgress = 0.0f;
        }
        wrapped = 1;
    }

    if (events == NULL)
    {
        return wrapped;
    }

    events->rootCurveValid = 0;
    events->rootDeltaZ = 0.0f;
    events->rootDeltaY = 0.0f;
    events->rootDeltaX = 0.0f;
    eventTable = objAnim->eventTable;
    if (eventTable != NULL)
    {
        events->triggerCount = 0;
        eventCount = objAnim->eventTable->byteCount >> 1;
        if (eventCount != 0)
        {
            previousFrame = (int)(512.0f * previousProgress);
            currentFrame = (int)(512.0f * objAnim->currentMoveProgress);
            scanMode = OBJANIM_EVENT_SCAN_FORWARD;
            if (currentFrame < previousFrame)
            {
                scanMode |= OBJANIM_EVENT_SCAN_WRAPPED;
            }
            if (progressDelta < 0.0f)
            {
                scanMode |= OBJANIM_EVENT_SCAN_REVERSE;
            }

            for (eventIndex = 0; eventIndex < eventCount && events->triggerCount < OBJANIM_EVENT_TRIGGER_CAPACITY;
                 eventIndex++)
            {
                eventFrame = ObjAnim_GetPackedEventFrame(objAnim->eventTable->entries[eventIndex]);
                eventId = ObjAnim_GetPackedEventId(objAnim->eventTable->entries[eventIndex]);
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
        moveData = (ObjAnimMoveData*)(state->moveCache[state->moveCacheSlot] + OBJANIM_CACHED_MOVE_DATA_OFFSET);
    }
    else
    {
        moveData = (ObjAnimMoveData*)bank->animDef->moveData[state->moveCacheSlot];
    }
    if (moveData->rootCurveOffset != 0)
    {
        events->rootCurveValid = 1;
        axis = (s16*)ObjAnim_GetMoveDataRootCurve(moveData);
        rootScale = ((ObjAnimRootCurve*)axis)->scale * objAnim->rootMotionScale;
        segmentCount = ((ObjAnimRootCurve*)axis)->sampleCount - 1;
        axis += OBJANIM_ROOT_CURVE_AXIS_DATA_OFFSET / sizeof(*axis);
        sampleSpan = segmentCount;
        previousScaledSample = sampleSpan * previousProgress;
        previousSampleIndex = previousScaledSample;
        previousFraction = previousScaledSample - previousSampleIndex;
        currentScaledSample = sampleSpan * objAnim->currentMoveProgress;
        currentSampleIndex = currentScaledSample;
        currentFraction = currentScaledSample - currentSampleIndex;

        blendAxis = NULL;
        if (state->eventState != 0)
        {
            blendWeight = state->eventState / 16384.0f;
            moveWeight = OBJANIM_PROGRESS_ONE - blendWeight;
            if ((bank->animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) != 0)
            {
                moveData =
                    (ObjAnimMoveData*)(state->blendMoveCache[state->blendCacheSlot] + OBJANIM_CACHED_MOVE_DATA_OFFSET);
            }
            else
            {
                moveData = (ObjAnimMoveData*)bank->animDef->moveData[state->blendCacheSlot];
            }
            blendCurve = ObjAnim_GetMoveDataRootCurve(moveData);
            blendAxis = (s16*)blendCurve;
            blendAxis += 3;
        }
        else
        {
            blendWeight = 0.0f;
            moveWeight = OBJANIM_PROGRESS_ONE;
        }

        axisIndex = 0;
        do
        {
            if (*axis != 0)
            {
                axis++;
                if (blendAxis != NULL)
                {
                    blendAxis++;
                }
                at = (s16*)((previousSampleIndex << 1) + (int)axis);
                previousAxisValue = moveWeight * at[0];
                if (blendAxis != NULL)
                {
                    previousAxisValue += blendWeight * blendAxis[previousSampleIndex];
                }
                previousAxisNextValue = moveWeight * at[1];
                if (blendAxis != NULL)
                {
                    previousAxisNextValue += blendWeight * blendAxis[previousSampleIndex + 1];
                }
                previousInterp = previousAxisValue + previousFraction * (previousAxisNextValue - previousAxisValue);

                at = (s16*)((currentSampleIndex << 1) + (int)axis);
                currentAxisValue = moveWeight * at[0];
                if (blendAxis != NULL)
                {
                    currentAxisValue += blendWeight * blendAxis[currentSampleIndex];
                }
                currentAxisNextValue = moveWeight * at[1];
                if (blendAxis != NULL)
                {
                    currentAxisNextValue += blendWeight * blendAxis[currentSampleIndex + 1];
                }
                currentInterp = currentAxisValue + currentFraction * (currentAxisNextValue - currentAxisValue);

                if (progressDelta > 0.0f)
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
                    (&events->rootYaw)[axisIndex - OBJANIM_ROOT_CURVE_TRANSLATION_AXIS_COUNT] = value;
                }

                axis += segmentCount + 1;
                if (blendAxis != NULL)
                {
                    blendAxis += segmentCount + 1;
                }
            }
            else
            {
                axis++;
                if (blendAxis != NULL)
                {
                    blendAxis++;
                }
                if (axisIndex < OBJANIM_ROOT_CURVE_TRANSLATION_AXIS_COUNT)
                {
                    (&events->rootDeltaX)[axisIndex] = 0.0f;
                }
                else
                {
                    (&events->rootYaw)[axisIndex - OBJANIM_ROOT_CURVE_TRANSLATION_AXIS_COUNT] = 0;
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

int ObjAnim_SetMoveProgress(ObjAnimComponent* objAnim, f32 moveProgress)
{
    if (moveProgress > OBJANIM_SET_MOVE_PROGRESS_MAX)
    {
        moveProgress = OBJANIM_SET_MOVE_PROGRESS_MAX;
    }
    else if (moveProgress < 0.0f)
    {
        moveProgress = 0.0f;
    }
    objAnim->currentMoveProgress = moveProgress;
    return 0;
}

int ObjAnim_SetCurrentMove(void* objAnimHandle, int moveId, f32 moveProgress, u8 moveControlFlags)
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
    if (moveProgress > OBJANIM_PROGRESS_ONE)
    {
        moveProgress = OBJANIM_PROGRESS_ONE;
    }
    else if (moveProgress < 0.0f)
    {
        moveProgress = 0.0f;
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
        ObjHitReact_LoadMoveEntries((ObjAnimComponent*)objAnimHandle, bank, objAnim->romDefNo, hitState, requestedMoveId,
                                    0);
    }
    if (objAnim->eventTable != NULL)
    {
        ObjAnim_LoadMoveEvents((u8*)objAnimHandle, objAnim->romDefNo, objAnim->eventTable, requestedMoveId, 0);
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
        moveData = (ObjAnimMoveData*)(state->moveCache[state->moveCacheSlot] + OBJANIM_CACHED_MOVE_DATA_OFFSET);
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
        state->frameLength = state->frameLength - OBJANIM_PROGRESS_ONE;
    }
    frameStep = moveData->frameControl & OBJANIM_FRAME_STEP_MASK;
    if ((frameStep != 0) && ((moveControlFlags & OBJANIM_MOVE_CONTROL_SKIP_EVENT_COUNTDOWN) == 0))
    {
        state->savedFrameStep = state->frameStep;
        eventCountdownStep = 16384.0f / (float)frameStep;
        state->eventStep = eventCountdownStep;
        state->eventCountdown = OBJANIM_EVENT_COUNTDOWN_RESET;
    }
    else
    {
        state->eventCountdown = 0;
    }
    state->frameStep = 0.0f;
    state->framePhase = moveProgress * state->frameLength;
    return 0;
}

char gObjAnimMissingCachedMoveWarning[] =
    "<objanim.c -- setBlendMove> WARNING tried to load anim -1 from cache modno %d\n";
