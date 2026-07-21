#include "dolphin/os.h"
#include "main/objHitReact.h"
#include "main/objanim_internal.h"
#include "main/objhits.h"
#include "main/objanim.h"

/*
 * Retail string evidence labels this source-side path as objanim.c/setBlendMove.
 */
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

int Object_ObjAnimAdvanceMove(int objAnimHandle, f32 moveStepScale, f32 deltaTime, ObjAnimEventList* events)
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
            state->prevFramePhase =
                (state->prevFramePhase < gObjAnimProgressZero)
                    ? gObjAnimProgressZero
                    : ((state->prevFramePhase > prevFrameLength) ? prevFrameLength : state->prevFramePhase);
        }

        if ((state->moveControlFlags & OBJANIM_MOVE_CONTROL_HOLD_EVENT_COUNTDOWN) == 0)
        {
            countdown = (int)((f32)(s32)state->eventCountdown - ((f32)state->eventStep * deltaTime));
            value = (countdown < 0)
                        ? gObjAnimProgressZero
                        : (((f32)countdown > gObjAnimEventStepScale) ? gObjAnimEventStepScale : (f32)countdown);
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

int Object_ObjAnimSetMoveProgress(ObjAnimComponent* objAnim, f32 moveProgress)
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
Object_ObjAnimSetMove(int objAnimHandle, int moveId, f32 moveProgress, int moveControlFlags)
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
        eventCountdownStep = gObjAnimEventStepScale / (float)(s32)frameCount;
        bank->currentState->eventStep = eventCountdownStep;
    }
}

char gObjAnimMissingCachedMoveWarning[] =
    "<objanim.c -- setBlendMove> WARNING tried to load anim -1 from cache modno %d\n";
