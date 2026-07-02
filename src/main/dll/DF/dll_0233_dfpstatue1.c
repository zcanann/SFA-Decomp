/*
 * DragonRock Palace statue (DLL 0x233; "DFP_Statue1") - a sound-emitting
 * statue. While its loop game bit and 0xedf are set it runs trigger
 * sequence 0 and keeps a looped object sound alive; once stateFlags is
 * raised it runs sequence 1 and stops. A stop timer clears one of a set
 * of related game bits per loopSfxId. The DLL also exports the perchwitch
 * stub descriptor as a sibling object.
 */
#include "main/dll/crate2.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"

#define DFPSTATUE1_OBJFLAG_HIDDEN 0x4000

extern u32 sfxplayer_updateState(int obj, u32 unused, int animUpdate);
extern f32 timeDelta;

#pragma dont_inline on
void dfpstatue1_updateState(DfpStatue1Object* obj)
{
    DfpStatue1State* state;
    s16 loopBit;

    state = obj->state;
    loopBit = GameBit_Get(state->loopSfxId);
    if ((state->loopActive == 0) && (loopBit != 0) &&
        (GameBit_Get(0xedf) != 0))
    {
        (*gObjectTriggerInterface)->runSequence(0, obj, 0xffffffff);
        state->loopActive = 1;
    }
    if ((state->stateFlags != 0) && (state->loopActive != 0) && (GameBit_Get(0xedf) != 0))
    {
        GameBit_Set(state->loopSfxId, 0);
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
                GameBit_Set(0x66e, 0);
                break;
            case 0x673:
                GameBit_Set(0x66f, 0);
                break;
            case 0x674:
                GameBit_Set(0x670, 0);
                break;
            case 0x675:
                GameBit_Set(0x9f5, 0);
                break;
            }
        }
    }
}
#pragma dont_inline reset

int dfpstatue1_getExtraSize(void) { return 0xa; }
int dfpstatue1_getObjectTypeId(void) { return 0x0; }

void dfpstatue1_free(void)
{
}

void dfpstatue1_render(void)
{
}

void dfpstatue1_hitDetect(void)
{
}

void dfpstatue1_update(DfpStatue1Object* obj) { dfpstatue1_updateState(obj); }

void dfpstatue1_init(DfpStatue1Object* obj, DfpStatue1MapData* mapData)
{
    DfpStatue1State* state = obj->state;
    s16 yaw = (s16)(mapData->yawByte << 8);

    obj->yaw = yaw;
    obj->updateState = sfxplayer_updateState;
    state->effectPairCount = mapData->effectPairCount;
    state->triggerSfxId = mapData->triggerSfxId;
    state->loopSfxId = mapData->loopSfxId;
    if (GameBit_Get((int)state->loopSfxId) != 0)
    {
        state->loopActive = 1;
    }
    state->loopSfxStopTimer = 0;
    state->stateFlags = 0;
    obj->objectFlags |= DFPSTATUE1_OBJFLAG_HIDDEN;
}

void dfpstatue1_release(void)
{
}

void dfpstatue1_initialise(void)
{
}

ObjectDescriptor gDfpstatue1ObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dfpstatue1_initialise,
    (ObjectDescriptorCallback)dfpstatue1_release,
    0,
    (ObjectDescriptorCallback)dfpstatue1_init,
    (ObjectDescriptorCallback)dfpstatue1_update,
    (ObjectDescriptorCallback)dfpstatue1_hitDetect,
    (ObjectDescriptorCallback)dfpstatue1_render,
    (ObjectDescriptorCallback)dfpstatue1_free,
    (ObjectDescriptorCallback)dfpstatue1_getObjectTypeId,
    dfpstatue1_getExtraSize,
};

ObjectDescriptor gDfperchwitchObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dfperchwitch_initialise,
    (ObjectDescriptorCallback)dfperchwitch_release,
    0,
    (ObjectDescriptorCallback)dfperchwitch_init,
    (ObjectDescriptorCallback)dfperchwitch_update,
    (ObjectDescriptorCallback)dfperchwitch_hitDetect,
    (ObjectDescriptorCallback)dfperchwitch_render,
    (ObjectDescriptorCallback)dfperchwitch_free,
    (ObjectDescriptorCallback)dfperchwitch_getObjectTypeId,
    dfperchwitch_getExtraSize,
};

char sDfperchwitchInitNoLongerSupported[] = "<dfperchwitch Init>No Longer supported \n";
