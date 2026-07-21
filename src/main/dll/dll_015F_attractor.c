/*
 * attractor (DLL 0x15F) - a placement-driven object that joins object
 * group 0x1e and, on demand, reports either itself or a heading toward
 * the player. Its placement record carries its initial rotation, mode,
 * and scale.
 *
 * attractor_getTarget is the queried accessor: mode 1 returns the object;
 * mode 2 additionally faces the object at the player (atan2 of the
 * player-relative xz delta, biased by 0x8000) before returning it;
 * other modes report nothing.
 *
 * attractor_setScale exposes the placement scale halfword when the
 * mode byte is set. The object has no per-frame think/hit work
 * (update/hitDetect are empty) and renders through objRenderModelAndHitVolumes
 * at a fixed scale (lbl_803E43D0).
 */
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/obj_group.h"
#include "main/object_api.h"
#include "main/object_descriptor.h"
#include "main/object_render.h"
#include "main/dll/dll_015F_attractor.h"
#include "main/vecmath.h"

#define ATTRACTOR_OBJ_GROUP 0x1e

void attractor_getTarget(GameObject* obj, GameObject** outTarget)
{
    GameObject* target = NULL;
    AttractorPlacement* placement = (AttractorPlacement*)obj->anim.placementData;
    s8 mode = placement->mode;
    switch (mode)
    {
    case ATTRACTOR_MODE_NONE:
        break;
    case ATTRACTOR_MODE_RETURN_SELF:
        target = obj;
        break;
    case ATTRACTOR_MODE_FACE_PLAYER:
    {
        GameObject* player = Obj_GetPlayerObject();
        int angle = atan2i((int)(player->anim.localPosX - obj->anim.localPosX),
                           (int)(player->anim.localPosZ - obj->anim.localPosZ));
        obj->anim.rotX = (s16)(angle + 0x8000);
        target = obj;
        break;
    }
    }
    *outTarget = target;
}

int attractor_setScale(GameObject* obj)
{
    AttractorPlacement* placement = (AttractorPlacement*)obj->anim.placementData;
    if (placement->mode != ATTRACTOR_MODE_NONE)
    {
        return placement->scale;
    }
    return 0;
}

int attractor_getExtraSize(void)
{
    return 0x0;
}
int attractor_getObjectTypeId(void)
{
    return 0x0;
}

void attractor_free(GameObject* obj)
{
    ObjGroup_RemoveObject((int)obj, ATTRACTOR_OBJ_GROUP);
}

void attractor_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void attractor_hitDetect(void)
{
}

void attractor_update(void)
{
}

void attractor_init(GameObject* obj, AttractorPlacement* placement)
{
    ObjGroup_AddObject((u32)obj, ATTRACTOR_OBJ_GROUP);
    {
        s8 rotation = placement->rotXByte;
        s16 rotX = rotation << 8;
        obj->anim.rotX = rotX;
    }
}

void attractor_release(void)
{
}

void attractor_initialise(void)
{
}

ObjectDescriptor12 gAttractorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    (ObjectDescriptorCallback)attractor_initialise,
    (ObjectDescriptorCallback)attractor_release,
    0,
    (ObjectDescriptorCallback)attractor_init,
    (ObjectDescriptorCallback)attractor_update,
    (ObjectDescriptorCallback)attractor_hitDetect,
    (ObjectDescriptorCallback)attractor_render,
    (ObjectDescriptorCallback)attractor_free,
    (ObjectDescriptorCallback)attractor_getObjectTypeId,
    attractor_getExtraSize,
    (ObjectDescriptorCallback)attractor_setScale,
    (ObjectDescriptorCallback)attractor_getTarget,
};
