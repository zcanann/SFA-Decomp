/*
 * DragonRock Palace statue (DLL 0x233; "DFP_Statue1") - a sound-emitting
 * statue. While its loop game bit and 0xedf are set it runs trigger
 * sequence 0 and keeps a looped object sound alive; once stateFlags is
 * raised it runs sequence 1 and stops. A stop timer clears one of a set
 * of related game bits per loopSfxId. The DLL's descriptors (and the
 * perchwitch stub sibling) live in dll_0234_dfpperchsw.
 */
#include "main/dll/crate2.h"
#include "main/dll/crate.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"

#define DFPSTATUE1_OBJFLAG_HIDDEN 0x4000

#pragma dont_inline on
void dfpstatue1_updateState(DfpStatue1Object* obj)
{
    DfpStatue1State* state;
    s16 loopBit;

    state = obj->state;
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
        state->loopSfxStopTimer = (s16)((float)state->loopSfxStopTimer - timeDelta);
        Sfx_KeepAliveLoopedObjectSound((int)obj, SFXTRIG_treadlpc);
        if (state->loopSfxStopTimer <= 0)
        {
            state->loopSfxStopTimer = 0;
            switch (state->loopSfxId)
            {
            case 0x672:
                mainSetBits(0x66e, 0);
                break;
            case 0x673:
                mainSetBits(0x66f, 0);
                break;
            case 0x674:
                mainSetBits(0x670, 0);
                break;
            case 0x675:
                mainSetBits(0x9f5, 0);
                break;
            }
        }
    }
}
#pragma dont_inline reset

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

void DFP_Statue1_update(DfpStatue1Object* obj)
{
    dfpstatue1_updateState(obj);
}

void DFP_Statue1_init(DfpStatue1Object* obj, DfpStatue1MapData* mapData)
{
    DfpStatue1State* state = obj->state;
    s16 yaw = (s16)(mapData->yawByte << 8);

    obj->yaw = yaw;
    obj->updateState = sfxplayer_updateState;
    state->effectPairCount = mapData->effectPairCount;
    state->triggerSfxId = mapData->triggerSfxId;
    state->loopSfxId = mapData->loopSfxId;
    if (mainGetBit((int)state->loopSfxId) != 0)
    {
        state->loopActive = 1;
    }
    state->loopSfxStopTimer = 0;
    state->stateFlags = 0;
    obj->objectFlags |= DFPSTATUE1_OBJFLAG_HIDDEN;
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
