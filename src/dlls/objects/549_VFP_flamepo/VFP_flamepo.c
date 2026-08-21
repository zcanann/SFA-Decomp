/* VFP_flamepo (DLL 0x0225) */
#include "dlls/object_descriptor.h"
#include "main/dll/dll_00C4_tricky.h"
#include "main/gamebits.h"
#include "main/objprint_render_api.h"
#include "main/objtype.h"
#include "sys/objects/lifecycle.h"

#define VFP_FLAMEPOINT_OBJFLAG_HIDDEN             0x4000
#define VFP_FLAMEPOINT_OBJFLAG_HITDETECT_DISABLED 0x2000


#define VFP_FLAMEPOINT_TRICKY_COMMAND_TYPE 4

typedef struct VfpFlamePointData
{
    s16 showGameBit;  /* 0x0 */
    s16 checkGameBit; /* 0x2 */
    s8 counter;       /* 0x4 */
    u8 done : 1;      /* 0x5 bit 7 */
    u8 noCheck : 1;   /* 0x5 bit 6 */
    u8 pad06[2];
} VfpFlamePointData;

typedef struct VfpFlamePointMapData
{
    ObjPlacement base;
    u8 pad18[2];
    s16 counterInit;  /* 0x1a */
    s16 noCheck;      /* 0x1c */
    s16 showGameBit;  /* 0x1e */
    s16 checkGameBit; /* 0x20 */
} VfpFlamePointMapData;

STATIC_ASSERT(sizeof(VfpFlamePointData) == 0x08);
STATIC_ASSERT(offsetof(VfpFlamePointData, showGameBit) == 0x00);
STATIC_ASSERT(offsetof(VfpFlamePointData, checkGameBit) == 0x02);
STATIC_ASSERT(offsetof(VfpFlamePointData, counter) == 0x04);
STATIC_ASSERT(offsetof(VfpFlamePointMapData, counterInit) == 0x1A);
STATIC_ASSERT(offsetof(VfpFlamePointMapData, noCheck) == 0x1C);
STATIC_ASSERT(offsetof(VfpFlamePointMapData, showGameBit) == 0x1E);
STATIC_ASSERT(offsetof(VfpFlamePointMapData, checkGameBit) == 0x20);

int vfpflamepoint_countdownCallback(GameObject* obj, int x)
{
    VfpFlamePointData* extra = obj->extra;

    if (extra != NULL)
    {
        extra->counter -= x;
        return extra->counter <= 0;
    }
    return 0;
}

int VFP_flamepoint_getExtraSize(void)
{
    return sizeof(VfpFlamePointData);
}

void VFP_flamepoint_update(GameObject* obj)
{
    VfpFlamePointData* d;
    void* tricky;

    d = obj->extra;
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    if (!d->done && (d->checkGameBit == -1 || mainGetBit(d->checkGameBit) != 0))
    {
        if (d->counter <= 0 && !d->done)
        {
            if (d->showGameBit != -1)
            {
                mainSetBits(d->showGameBit, 1);
                d->done = 1;
            }
        }
        else
        {
            tricky = getTrickyObject();
            if (tricky != NULL)
            {
                f32 dist = 35.0f;

                if (d->noCheck || (void*)objGetNearestTypeTo(5, obj, &dist) == NULL)
                {
                    if (obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE)
                    {
                        TRICKY_INTERFACE(tricky)->sideCommandEnable((GameObject*)tricky, obj,
                                                                   TRICKY_COMMAND_KIND_PRIORITY,
                                                                   VFP_FLAMEPOINT_TRICKY_COMMAND_TYPE);
                    }
                    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                    objUpdateHitVolumeTransforms(obj);
                }
            }
        }
    }
    else
    {
        u8 v = mainGetBit(d->showGameBit);

        if (!(d->done = v))
        {
            d->counter = (s8)((VfpFlamePointMapData*)obj->anim.placementData)->counterInit;
        }
    }
}

void VFP_flamepoint_init(GameObject* obj, s8* def)
{
    VfpFlamePointData* d = (VfpFlamePointData*)obj->extra;
    VfpFlamePointMapData* mapData = (VfpFlamePointMapData*)def;

    d->counter = (s8)mapData->counterInit;
    d->noCheck = (u8)mapData->noCheck;
    d->showGameBit = mapData->showGameBit;
    d->checkGameBit = mapData->checkGameBit;
    obj->objectFlags |=
        (VFP_FLAMEPOINT_OBJFLAG_HIDDEN | VFP_FLAMEPOINT_OBJFLAG_HITDETECT_DISABLED);
}

ObjectDescriptor gVFP_flamepointObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)VFP_flamepoint_init,
    (ObjectDescriptorCallback)VFP_flamepoint_update,
    0,
    0,
    0,
    0,
    (ObjectDescriptorExtraSizeCallback)VFP_flamepoint_getExtraSize,
};
