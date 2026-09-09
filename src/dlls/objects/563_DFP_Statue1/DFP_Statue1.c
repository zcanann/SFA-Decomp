/*
 * Ocean Force Point Temple statue. Its animation callback drives the effect
 * GameBits from sequence events. Activation requests run statue sequences
 * while the ring puzzle is active; a timed effect keeps the looped sound alive.
 */
#include "dlls/objects/563_DFP_Statue1.h"
#include "dlls/objects/562_DFP_RotateP.h"

#include "main/audio/sfx_keep_alive_api.h"
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
            mainSetBits(state->activationGameBit + 5, 1);
            break;
        case DFP_STATUE1_EVENT_DEACTIVATE:
            mainSetBits(state->activationGameBit + 5, 0);
            state->deactivationPending = 1;
            break;
        case DFP_STATUE1_EVENT_VARIANT:
            switch (state->activationGameBit)
            {
            case DFP_STATUE1_BASE_VARIANT_A:
                mainSetBits(GAMEBIT_DFP_STATUE1_VARIANT_A, 1);
                state->effectTimer = DFP_STATUE1_VARIANT_TIMER_FRAMES;
                break;
            case DFP_STATUE1_BASE_VARIANT_B:
                mainSetBits(GAMEBIT_DFP_STATUE1_VARIANT_B, 1);
                state->effectTimer = DFP_STATUE1_VARIANT_TIMER_FRAMES;
                break;
            case DFP_STATUE1_BASE_VARIANT_C:
                mainSetBits(GAMEBIT_DFP_STATUE1_VARIANT_C, 1);
                state->effectTimer = DFP_STATUE1_VARIANT_TIMER_FRAMES;
                break;
            case DFP_STATUE1_BASE_VARIANT_D:
                mainSetBits(GAMEBIT_DFP_STATUE1_VARIANT_D, 1);
                state->effectTimer = DFP_STATUE1_VARIANT_TIMER_FRAMES;
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
    s16 activationRequested;

    state = obj->extra;
    activationRequested = mainGetBit(state->activationGameBit);
    if ((state->sequenceActive == 0) && (activationRequested != 0) && (mainGetBit(DFP_ROTATEP_GAMEBIT_RING_ACTIVE) != 0))
    {
        (*gObjectTriggerInterface)->runSequence(0, obj, 0xffffffff);
        state->sequenceActive = 1;
    }
    if ((state->deactivationPending != 0) && (state->sequenceActive != 0) && (mainGetBit(DFP_ROTATEP_GAMEBIT_RING_ACTIVE) != 0))
    {
        mainSetBits(state->activationGameBit, 0);
        (*gObjectTriggerInterface)->runSequence(1, obj, 0xffffffff);
        state->sequenceActive = 0;
        state->deactivationPending = 0;
    }
    if (state->effectTimer != 0)
    {
        state->effectTimer = (float)state->effectTimer - timeDelta;
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_treadlpc);
        if (state->effectTimer <= 0)
        {
            state->effectTimer = 0;
            switch (state->activationGameBit)
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
    return sizeof(DfpStatue1State);
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

void DFP_Statue1_init(GameObject* obj, DfpStatue1PlacementPrefix* mapData)
{
    DfpStatue1State* state = obj->extra;
    s16 rotationX = (s16)(mapData->rotationXByte << 8);

    obj->anim.rotX = rotationX;
    obj->animEventCallback = dfpstatue1_SeqFn;
    state->unknown07 = mapData->unknown19;
    state->unknown00 = mapData->unknown1E;
    state->activationGameBit = mapData->activationGameBit;
    if (mainGetBit((int)state->activationGameBit) != 0)
    {
        state->sequenceActive = 1;
    }
    state->effectTimer = 0;
    state->deactivationPending = 0;
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
    DFP_Statue1_initialise,
    DFP_Statue1_release,
    0,
    (ObjectDescriptorCallback)DFP_Statue1_init,
    (ObjectDescriptorCallback)DFP_Statue1_update,
    DFP_Statue1_hitDetect,
    DFP_Statue1_render,
    DFP_Statue1_free,
    (ObjectDescriptorCallback)DFP_Statue1_getObjectTypeId,
    DFP_Statue1_getExtraSize,
};
