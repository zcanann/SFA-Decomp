/* DFP_PowerSl effect controller (DLL 572). It starts its
 * sequence at a configured frame, emits the configured particle effect while
 * its disable bit is clear, and emits a twenty-particle burst on priority hits.
 */
#include "dlls/objects/572_DFP_PowerSl.h"

#include "main/dll/partfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/objseq.h"

#define DFPPOWERSL_DEFAULT_START_FRAME 1
#define DFPPOWERSL_DEFAULT_EFFECT_ID 1
#define DFPPOWERSL_ROTATION_BYTE_SHIFT 8
#define DFPPOWERSL_HIT_PRIORITY 0x13
#define DFPPOWERSL_HIT_VOLUME_ID 1
#define DFPPOWERSL_HIT_EFFECT_ID 0x39e
#define DFPPOWERSL_HIT_EFFECT_COUNT 0x14

static inline DfpPowerSlState* dfppowersl_getState(GameObject* obj)
{
    return obj->extra;
}

int dfppowersl_spawnHitEffects(GameObject* obj)
{
    int i;
    GameObject* outObj;

    outObj = NULL;
    if (obj == 0)
    {
        return 0;
    }
    i = ObjHits_GetPriorityHit(obj, &outObj, 0, 0);
    if ((outObj != NULL) && (i != 0))
    {
        i = 1;
        do
        {
            (*gPartfxInterface)->spawnObject(obj, DFPPOWERSL_HIT_EFFECT_ID, 0, PARTFXFLAG_1, 0xffffffff, 0);
        } while (i++ < DFPPOWERSL_HIT_EFFECT_COUNT);
    }
    return 0;
}

int dfppowersl_getExtraSize(void)
{
    return sizeof(DfpPowerSlState);
}

void dfppowersl_free(GameObject* obj)
{
    if (obj != 0)
    {
        (*gExpgfxInterface)->freeSource2((u32)obj);
    }
    return;
}

void dfppowersl_render(GameObject* obj)
{
    GameObject* powerSl;
    DfpPowerSlState* state;

    powerSl = obj;
    if ((u32)powerSl != 0)
    {
        state = dfppowersl_getState(powerSl);
        if (mainGetBit(state->disableEffectGameBit) == 0)
        {
            (*gPartfxInterface)
                ->spawnObject(powerSl, state->effectId, 0, PARTFXFLAG_4, 0xffffffff, 0);
            (*gPartfxInterface)
                ->spawnObject(powerSl, state->effectId, 0, PARTFXFLAG_1, 0xffffffff, 0);
        }
    }
    return;
}

void dfppowersl_update(GameObject* obj)
{
    GameObject* powerSl;
    DfpPowerSlState* state;

    powerSl = obj;
    if ((u32)powerSl != 0)
    {
        state = dfppowersl_getState(powerSl);
        (*gObjectTriggerInterface)->preempt((int)powerSl, state->sequenceStartFrame);
        (*gObjectTriggerInterface)->runSequence(0, powerSl, 0xffffffff);
    }
    return;
}

void dfppowersl_init(GameObject* obj, DfpPowerSlPlacementPrefix* mapData)
{
    DfpPowerSlState* state;

    if (obj != 0)
    {
        state = dfppowersl_getState(obj);
        if (mapData->sequenceStartFrame <= 0)
        {
            mapData->sequenceStartFrame = DFPPOWERSL_DEFAULT_START_FRAME;
        }
        if (mapData->effectId <= 0)
        {
            mapData->effectId = DFPPOWERSL_DEFAULT_EFFECT_ID;
        }
        obj->animEventCallback = dfppowersl_spawnHitEffects;
        state->sequenceStartFrame = mapData->sequenceStartFrame;
        state->effectId = mapData->effectId;
        state->disableEffectGameBit = mapData->disableEffectGameBit;
        obj->anim.rotX = mapData->rotationXByte << DFPPOWERSL_ROTATION_BYTE_SHIFT;
        ObjHits_SetHitVolumeSlot(&obj->anim, DFPPOWERSL_HIT_PRIORITY, DFPPOWERSL_HIT_VOLUME_ID, 0);
    }
    return;
}

ObjectDescriptor gDfppowerslObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)dfppowersl_init,
    (ObjectDescriptorCallback)dfppowersl_update,
    0,
    (ObjectDescriptorCallback)dfppowersl_render,
    (ObjectDescriptorCallback)dfppowersl_free,
    0,
    dfppowersl_getExtraSize,
};
