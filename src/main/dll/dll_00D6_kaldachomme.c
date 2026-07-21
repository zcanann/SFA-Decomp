/*
 * kaldachomme (DLL 0x00D6) - the KaldaChompMe animated chomping-mouth
 * object.
 *
 * KaldaChompMe drives a single animation move toward a target progress
 * value (state @0x00..0x0C) at state->step per frame; setLinkedMouthMode
 * looks up a paired mouth object by placement-mapId and (re)arms its
 * open/close move (mode 1 = moveId 0, mode 2 = moveId 1). render draws
 * via objRenderModelAndHitVolumes when the visible flag is set; init seeds the
 * rotation from the placement bytes and starts move 0.
 */
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/dll/dll_00D6_kaldachomme_api.h"
#include "main/obj_placement.h"
#include "main/frame_timing.h"
#include "main/object_descriptor.h"
#include "main/object_render.h"

#define KALDACHOMME_OBJFLAG_HITDETECT_DISABLED 0x2000

void kaldachompme_setLinkedMouthMode(u8* obj, KaldaChompMeLinkedMode mode)
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
        case KALDACHOMPME_LINKED_MOVE_0:
            state->targetProgress = gKaldaChompOne;
            state->progress = gKaldaChompZero;
            state->step = gKaldaChompLinkedMouthStep;
            state->moveId = 0;
            break;
        case KALDACHOMPME_LINKED_MOVE_1:
            state->targetProgress = gKaldaChompOne;
            state->progress = gKaldaChompZero;
            state->step = gKaldaChompLinkedMouthStep;
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

void KaldaChompMe_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 renderFlag)
{
    if (renderFlag != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, gKaldaChompOne);
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
        if (step > gKaldaChompZero)
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

void KaldaChompMe_init(GameObject* obj, KaldaChompMePlacement* placement)
{
    (obj)->anim.rotZ = (s16)(placement->rotZByte << 8);
    (obj)->anim.rotY = (s16)(placement->rotYByte << 8);
    (obj)->anim.rotX = (s16)(placement->rotXByte << 8);
    (obj)->objectFlags = (u16)((obj)->objectFlags | KALDACHOMME_OBJFLAG_HITDETECT_DISABLED);
    ObjAnim_SetCurrentMove((int)obj, 0, gKaldaChompZero, 0);
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
