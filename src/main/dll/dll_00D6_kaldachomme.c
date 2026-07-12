/*
 * kaldachomme (DLL 0x00D6) - the KaldaChompMe animated chomping-mouth
 * object plus the data records for several sibling objects whose code
 * lives in neighbouring DLLs (kaldachompspit, pinponspike, pollen,
 * pollenfragment).
 *
 * KaldaChompMe drives a single animation move toward a target progress
 * value (state @0x00..0x0C) at state->step per frame; setLinkedMouthMode
 * looks up a paired mouth object by placement-mapId and (re)arms its
 * open/close move (mode 1 = moveId 0, mode 2 = moveId 1). render draws
 * via objRenderModelAndHitVolumes when the visible flag is set; init seeds the
 * rotation from the placement bytes and starts move 0.
 *
 * This TU also owns the ObjectDescriptors and the PollenFragmentConfig
 * table (the config pointer table) for the sibling pollen-fragment object.
 */
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/dll/xyzanimator.h"
#include "main/obj_placement.h"
#include "main/dll/VF/vf_shared.h"

typedef struct KaldaChompMeState
{
    f32 progress;
    f32 step;
    f32 targetProgress;
    u8 moveId;
    u8 pad0D[3];
} KaldaChompMeState;

typedef struct KaldaChompMePlacement
{
    ObjPlacement head;
    u8 yawBits;   /* 0x18 */
    u8 pitchBits; /* 0x19 */
    u8 rollBits;  /* 0x1a */
} KaldaChompMePlacement;

STATIC_ASSERT(offsetof(KaldaChompMePlacement, yawBits) == 0x18);
STATIC_ASSERT(offsetof(KaldaChompMePlacement, pitchBits) == 0x19);
STATIC_ASSERT(offsetof(KaldaChompMePlacement, rollBits) == 0x1a);

#define KALDACHOMME_OBJFLAG_HITDETECT_DISABLED 0x2000

extern f32 lbl_803E30D0;
extern f32 lbl_803E30D4;
extern f32 lbl_803E30D8;

int KaldaChompSpit_getExtraSize(void);
int KaldaChompSpit_getObjectTypeId(void);

void kaldachompme_setLinkedMouthMode(u8* obj, u8 mode)
{
    KaldaChompMeState* state;
    GameObject* linkedObj;

    if (obj == NULL)
    {
        return;
    }
    switch (((GameObject*)obj)->anim.placement->mapId)
    {
    case 0x43d14:
        linkedObj = ObjList_FindObjectById(0x4b3b5);
        break;
    case 0x41be9:
        linkedObj = ObjList_FindObjectById(0x4b3f9);
        break;
    case 0x41cc4:
        linkedObj = ObjList_FindObjectById(0x4b402);
        break;
    case 0x41cc5:
        linkedObj = ObjList_FindObjectById(0x4b403);
        break;
    case 0x41cc6:
        linkedObj = ObjList_FindObjectById(0x4b404);
        break;
    case 0x41cc7:
        linkedObj = ObjList_FindObjectById(0x4b40b);
        break;
    case 0x41cc8:
        linkedObj = ObjList_FindObjectById(0x4b40c);
        break;
    case 0x41cc9:
        linkedObj = ObjList_FindObjectById(0x4b40f);
        break;
    case 0x41cd2:
        linkedObj = ObjList_FindObjectById(0x4b410);
        break;
    case 0x41ccc:
        linkedObj = ObjList_FindObjectById(0x4b411);
        break;
    case 0x41cd5:
        linkedObj = ObjList_FindObjectById(0x4b414);
        break;
    case 0x41cd6:
        linkedObj = ObjList_FindObjectById(0x4b415);
        break;
    case 0x41cd9:
        linkedObj = ObjList_FindObjectById(0x4b453);
        break;
    default:
        return;
    }
    state = linkedObj->extra;
    if (state != NULL)
    {
        switch (mode)
        {
        case 1:
            state->targetProgress = lbl_803E30D0;
            state->progress = lbl_803E30D4;
            state->step = lbl_803E30D8;
            state->moveId = 0;
            break;
        case 2:
            state->targetProgress = lbl_803E30D0;
            state->progress = lbl_803E30D4;
            state->step = lbl_803E30D8;
            state->moveId = 1;
            break;
        }
    }
}

int KaldaChompMe_getExtraSize(void)
{
    return sizeof(KaldaChompMeState);
}

int KaldaChompMe_getObjectTypeId(void)
{
    return 0;
}

void KaldaChompMe_free(void)
{
}

void KaldaChompMe_render(int p1, int p2, int p3, int p4, int p5, s8 renderFlag)
{
    if (renderFlag != 0)
    {
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E30D0);
    }
}

void KaldaChompMe_hitDetect(void)
{
}

void KaldaChompMe_update(GameObject* obj)
{
    f32 target;
    f32 current;
    f32 step;
    KaldaChompMeState* extra;

    extra = (obj)->extra;
    current = extra->progress;
    target = extra->targetProgress;
    if (current != target)
    {
        step = extra->step;
        if (step > lbl_803E30D4)
        {
            if (current < target)
            {
                extra->progress = current + step * timeDelta;
            }
            else
            {
                extra->progress = target;
            }
        }
        else
        {
            if (current > target)
            {
                extra->progress = current + step * timeDelta;
            }
            else
            {
                extra->progress = target;
            }
        }
    }
    ObjAnim_SetCurrentMove((int)obj, extra->moveId, extra->progress, 0);
}

void KaldaChompMe_init(GameObject* obj, int params)
{
    KaldaChompMePlacement* placement = (KaldaChompMePlacement*)params;

    (obj)->anim.rotZ = (s16)(placement->yawBits << 8);
    (obj)->anim.rotY = (s16)(placement->pitchBits << 8);
    (obj)->anim.rotX = (s16)(placement->rollBits << 8);
    (obj)->objectFlags = (u16)((obj)->objectFlags | KALDACHOMME_OBJFLAG_HITDETECT_DISABLED);
    ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E30D4, 0);
}

void KaldaChompMe_release(void)
{
}

void KaldaChompMe_initialise(void)
{
}

ObjectDescriptor gKaldaChompMeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)KaldaChompMe_initialise,
    (ObjectDescriptorCallback)KaldaChompMe_release,
    0,
    (ObjectDescriptorCallback)KaldaChompMe_init,
    (ObjectDescriptorCallback)KaldaChompMe_update,
    (ObjectDescriptorCallback)KaldaChompMe_hitDetect,
    (ObjectDescriptorCallback)KaldaChompMe_render,
    (ObjectDescriptorCallback)KaldaChompMe_free,
    (ObjectDescriptorCallback)KaldaChompMe_getObjectTypeId,
    KaldaChompMe_getExtraSize,
};

ObjectDescriptor gKaldaChompSpitObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)KaldaChompSpit_initialise,
    (ObjectDescriptorCallback)KaldaChompSpit_release,
    0,
    (ObjectDescriptorCallback)KaldaChompSpit_init,
    (ObjectDescriptorCallback)KaldaChompSpit_update,
    (ObjectDescriptorCallback)KaldaChompSpit_hitDetect,
    (ObjectDescriptorCallback)KaldaChompSpit_render,
    (ObjectDescriptorCallback)KaldaChompSpit_free,
    (ObjectDescriptorCallback)KaldaChompSpit_getObjectTypeId,
    KaldaChompSpit_getExtraSize,
};

ObjectDescriptor gPinPonSpikeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)pinponspike_initialise,
    (ObjectDescriptorCallback)pinponspike_release,
    0,
    (ObjectDescriptorCallback)pinponspike_init,
    (ObjectDescriptorCallback)pinponspike_update,
    (ObjectDescriptorCallback)pinponspike_hitDetect,
    (ObjectDescriptorCallback)pinponspike_render,
    (ObjectDescriptorCallback)pinponspike_free,
    (ObjectDescriptorCallback)pinponspike_getObjectTypeId,
    pinponspike_getExtraSize,
};

ObjectDescriptor gPollenObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)Pollen_initialise,
    (ObjectDescriptorCallback)Pollen_release,
    0,
    (ObjectDescriptorCallback)Pollen_init,
    (ObjectDescriptorCallback)Pollen_update,
    (ObjectDescriptorCallback)Pollen_hitDetect,
    (ObjectDescriptorCallback)Pollen_render,
    (ObjectDescriptorCallback)Pollen_free,
    (ObjectDescriptorCallback)Pollen_getObjectTypeId,
    Pollen_getExtraSize,
};

PollenFragmentConfig lbl_80320538 = {
    0x0000, 0x049F, 0x00B9, 0x04BA, 0x04BA, -1, 0.2f, 0x0000, 0xC000,
};

PollenFragmentConfig lbl_8032054C = {
    0x02FA, 0x02FB, 0x0496, 0x068F, 0x068F, 0x068F, 0.4f, 0x0026, 0x7000,
};

PollenFragmentConfig lbl_80320560 = {
    0x02FA, 0x02FB, 0x0496, 0x068F, 0x068F, 0x068F, 0.4f, 0x0026, 0x2000,
};

PollenFragmentConfig lbl_80320574 = {
    0x02FA, 0x02FB, 0x0496, 0x068F, 0x068F, -1, 0.2f, 0x0000, 0x2000,
};

PollenFragmentConfig lbl_80320588 = {
    0x02FA, 0x02FB, 0x0496, 0x068F, 0x068F, 0x068F, 0.4f, 0x0026, 0x3000,
};

PollenFragmentConfig* lbl_8032059C[] = {
    &lbl_80320538, &lbl_8032054C, &lbl_80320560, &lbl_80320574, &lbl_80320588,
};

ObjectDescriptor gPollenFragmentObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)pollenfragment_initialise,
    (ObjectDescriptorCallback)pollenfragment_release,
    0,
    (ObjectDescriptorCallback)pollenfragment_init,
    (ObjectDescriptorCallback)pollenfragment_update,
    (ObjectDescriptorCallback)pollenfragment_hitDetect,
    (ObjectDescriptorCallback)pollenfragment_render,
    (ObjectDescriptorCallback)pollenfragment_free,
    (ObjectDescriptorCallback)pollenfragment_getObjectTypeId,
    pollenfragment_getExtraSize,
};
