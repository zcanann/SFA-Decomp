/*
 * Ocean Force Point Temple statue. Its animation callback drives the effect
 * GameBits from sequence events, while the object update keeps the statue's
 * looped sound alive and stops it once the sequence has completed.
 */
#include "main/audio/sfx_keep_alive_api.h"
#include "main/dll/DF/dll_0233_dfpstatue1.h"
#include "main/gamebits.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/objseq.h"

#define DFP_STATUE1_EVENT_ACTIVATE       1
#define DFP_STATUE1_EVENT_DEACTIVATE     2
#define DFP_STATUE1_EVENT_VARIANT        3
#define DFP_STATUE1_VARIANT_TIMER_FRAMES 0x96

#define DFP_STATUE1_BASE_VARIANT_A 0x672
#define DFP_STATUE1_BASE_VARIANT_B 0x673
#define DFP_STATUE1_BASE_VARIANT_C 0x674
#define DFP_STATUE1_BASE_VARIANT_D 0x675

#define GAMEBIT_DFP_STATUE1_VARIANT_A 0x66e
#define GAMEBIT_DFP_STATUE1_VARIANT_B 0x66f
#define GAMEBIT_DFP_STATUE1_VARIANT_C 0x670
#define GAMEBIT_DFP_STATUE1_VARIANT_D 0x9f5

u32 dfpstatue1_SeqFn(GameObject* obj, u32 unused, ObjSeqState* animUpdate)
{
    int event;
    DfpStatue1State* state;
    int i;

    state = obj->extra;
    animUpdate->flags = -1;
    animUpdate->movementState = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        event = animUpdate->eventIds[i];
        switch (event)
        {
        case DFP_STATUE1_EVENT_ACTIVATE:
            mainSetBits(state->loopSfxId + 5, 1);
            break;
        case DFP_STATUE1_EVENT_DEACTIVATE:
            mainSetBits(state->loopSfxId + 5, 0);
            state->stateFlags = 1;
            break;
        case DFP_STATUE1_EVENT_VARIANT:
            switch (state->loopSfxId)
            {
            case DFP_STATUE1_BASE_VARIANT_A:
                mainSetBits(GAMEBIT_DFP_STATUE1_VARIANT_A, 1);
                state->loopSfxStopTimer = DFP_STATUE1_VARIANT_TIMER_FRAMES;
                break;
            case DFP_STATUE1_BASE_VARIANT_B:
                mainSetBits(GAMEBIT_DFP_STATUE1_VARIANT_B, 1);
                state->loopSfxStopTimer = DFP_STATUE1_VARIANT_TIMER_FRAMES;
                break;
            case DFP_STATUE1_BASE_VARIANT_C:
                mainSetBits(GAMEBIT_DFP_STATUE1_VARIANT_C, 1);
                state->loopSfxStopTimer = DFP_STATUE1_VARIANT_TIMER_FRAMES;
                break;
            case DFP_STATUE1_BASE_VARIANT_D:
                mainSetBits(GAMEBIT_DFP_STATUE1_VARIANT_D, 1);
                state->loopSfxStopTimer = DFP_STATUE1_VARIANT_TIMER_FRAMES;
                break;
            }
            break;
        }
        animUpdate->eventIds[i] = 0;
    }
    return 0;
}

void dfpstatue1_updateState(GameObject* obj)
{
    DfpStatue1State* state;
    s16 loopBit;

    state = obj->extra;
    loopBit = mainGetBit(state->loopSfxId);
    if ((state->loopActive == 0) && (loopBit != 0) && (mainGetBit(0xedf) != 0))
    {
        (*gObjectTriggerInterface)->runSequence(0, obj, 0xffffffff);
        state->loopActive = 1;
    }
    if ((state->stateFlags != 0) && (state->loopActive != 0) && (mainGetBit(0xedf) != 0))
    {
        mainSetBits(state->loopSfxId, 0);
        (*gObjectTriggerInterface)->runSequence(1, obj, 0xffffffff);
        state->loopActive = 0;
        state->stateFlags = 0;
    }
    if (state->loopSfxStopTimer != 0)
    {
        state->loopSfxStopTimer = (float)state->loopSfxStopTimer - timeDelta;
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_treadlpc);
        if (state->loopSfxStopTimer <= 0)
        {
            state->loopSfxStopTimer = 0;
            switch (state->loopSfxId)
            {
            case DFP_STATUE1_BASE_VARIANT_A:
                mainSetBits(GAMEBIT_DFP_STATUE1_VARIANT_A, 0);
                break;
            case DFP_STATUE1_BASE_VARIANT_B:
                mainSetBits(GAMEBIT_DFP_STATUE1_VARIANT_B, 0);
                break;
            case DFP_STATUE1_BASE_VARIANT_C:
                mainSetBits(GAMEBIT_DFP_STATUE1_VARIANT_C, 0);
                break;
            case DFP_STATUE1_BASE_VARIANT_D:
                mainSetBits(GAMEBIT_DFP_STATUE1_VARIANT_D, 0);
                break;
            }
        }
    }
}

int DFP_Statue1_getExtraSize(void)
{
    return 0xa;
}
int DFP_Statue1_getObjectTypeId(void)
{
    return 0x0;
}

void DFP_Statue1_free(void)
{
}

void DFP_Statue1_render(void)
{
}

void DFP_Statue1_hitDetect(void)
{
}

void DFP_Statue1_update(GameObject* obj)
{
    dfpstatue1_updateState(obj);
}

void DFP_Statue1_init(GameObject* obj, DfpStatue1MapData* mapData)
{
    DfpStatue1State* state = obj->extra;
    s16 yaw = (s16)(mapData->yawByte << 8);

    obj->anim.rotX = yaw;
    obj->animEventCallback = dfpstatue1_SeqFn;
    state->effectPairCount = mapData->effectPairCount;
    state->triggerSfxId = mapData->triggerSfxId;
    state->loopSfxId = mapData->loopSfxId;
    if (mainGetBit((int)state->loopSfxId) != 0)
    {
        state->loopActive = 1;
    }
    state->loopSfxStopTimer = 0;
    state->stateFlags = 0;
    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN;
}

void DFP_Statue1_release(void)
{
}

void DFP_Statue1_initialise(void)
{
}

ObjectDescriptor gDfpstatue1ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DFP_Statue1_initialise,
    (ObjectDescriptorCallback)DFP_Statue1_release,
    0,
    (ObjectDescriptorCallback)DFP_Statue1_init,
    (ObjectDescriptorCallback)DFP_Statue1_update,
    (ObjectDescriptorCallback)DFP_Statue1_hitDetect,
    (ObjectDescriptorCallback)DFP_Statue1_render,
    (ObjectDescriptorCallback)DFP_Statue1_free,
    (ObjectDescriptorCallback)DFP_Statue1_getObjectTypeId,
    DFP_Statue1_getExtraSize,
};
