/* VFP_lavasta (DLL 0x0227) */
#include "dlls/object_descriptor.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "main/dll/dll_00A6_modgfx.h"
#include "main/dll/expgfx_interface.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/resource.h"
#include "main/vecmath.h"

#define VFP_LAVASTAR_RESOURCE_ID                 0xa6
#define VFP_LAVASTAR_PARTFX                     0x3a4


DllA6Interface** gVfpLavaPoolEffectResource;

typedef struct VfpLavaStarState
{
    f32 verticalVelocity;
    f32 delayRangeMin;
    f32 delayRangeMax;
    s16 gameBit;
    s16 effectTimer;
    u8 particleToggle;
    u8 pad11[3];
} VfpLavaStarState;

typedef struct VfpLavaStarMapData
{
    ObjPlacement base;
    u8 pad18[2];
    s16 heightOffset;
    u8 pad1C[2];
    s16 gameBit;
} VfpLavaStarMapData;

STATIC_ASSERT(sizeof(VfpLavaStarState) == 0x14);
STATIC_ASSERT(offsetof(VfpLavaStarState, verticalVelocity) == 0x00);
STATIC_ASSERT(offsetof(VfpLavaStarState, delayRangeMin) == 0x04);
STATIC_ASSERT(offsetof(VfpLavaStarState, delayRangeMax) == 0x08);
STATIC_ASSERT(offsetof(VfpLavaStarState, gameBit) == 0x0C);
STATIC_ASSERT(offsetof(VfpLavaStarState, effectTimer) == 0x0E);
STATIC_ASSERT(offsetof(VfpLavaStarState, particleToggle) == 0x10);
STATIC_ASSERT(offsetof(VfpLavaStarMapData, heightOffset) == 0x1A);
STATIC_ASSERT(offsetof(VfpLavaStarMapData, gameBit) == 0x1E);

int VFP_lavastar_getExtraSize(void)
{
    return sizeof(VfpLavaStarState);
}

int VFP_lavastar_getObjectTypeId(void)
{
    return 0x0;
}

void VFP_lavastar_free(GameObject* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
    (*gModgfxInterface)->freeSourceEffects((void*)obj);
}

void VFP_lavastar_render(void)
{
}

void VFP_lavastar_hitDetect(void)
{
}

void VFP_lavastar_update(GameObject* obj)
{
    VfpLavaStarMapData* mapData;
    VfpLavaStarState* state;

    mapData = (VfpLavaStarMapData*)obj->anim.placementData;
    state = obj->extra;
    obj->anim.localPosY += timeDelta * state->verticalVelocity;
    if (obj->anim.localPosY > 900.0f + mapData->base.posY)
    {
        state->verticalVelocity = 0.1f * (f32)randomGetRange(5, 0x14);
        obj->anim.localPosY = mapData->base.posY;
    }
    state->effectTimer += (s16)timeDelta;
    if (gVfpLavaPoolEffectResource != 0 && state->effectTimer >= 0x28)
    {
        (*(void (*)(int, int, int, int, int, int)) *
         (int*)(*(int*)gVfpLavaPoolEffectResource + 4))(
            (int)obj, 0, 0, 4, -1, 0);
        state->effectTimer = 0;
    }
    if (state->particleToggle == 0)
    {
        (*gPartfxInterface)->spawnObject(
            (void*)obj, VFP_LAVASTAR_PARTFX, NULL, 2, -1, NULL);
    }
    state->particleToggle ^= 1;
}

void VFP_lavastar_init(GameObject* obj, VfpLavaStarMapData* def)
{
    VfpLavaStarState* state;
    VfpLavaStarMapData* mapData;

    mapData = def;
    state = obj->extra;
    state->gameBit = mapData->gameBit;
    state->verticalVelocity = 0.1f * (f32)randomGetRange(10, 0x19);
    state->effectTimer = 0x14;
    obj->anim.localPosY = mapData->base.posY + (f32)(int)mapData->heightOffset;
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    state->delayRangeMin = (f32)randomGetRange(0x1e, 0x3c);
    state->delayRangeMax = (f32)randomGetRange(100, 200);
}

void VFP_lavastar_release(void)
{
    Resource_Release(gVfpLavaPoolEffectResource);
    gVfpLavaPoolEffectResource = NULL;
}

void VFP_lavastar_initialise(void)
{
    gVfpLavaPoolEffectResource = NULL;
    gVfpLavaPoolEffectResource = Resource_Acquire(VFP_LAVASTAR_RESOURCE_ID, 1);
}

ObjectDescriptor gVFP_lavastarObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)VFP_lavastar_initialise,
    (ObjectDescriptorCallback)VFP_lavastar_release,
    0,
    (ObjectDescriptorCallback)VFP_lavastar_init,
    (ObjectDescriptorCallback)VFP_lavastar_update,
    (ObjectDescriptorCallback)VFP_lavastar_hitDetect,
    (ObjectDescriptorCallback)VFP_lavastar_render,
    (ObjectDescriptorCallback)VFP_lavastar_free,
    (ObjectDescriptorCallback)VFP_lavastar_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)VFP_lavastar_getExtraSize,
};
