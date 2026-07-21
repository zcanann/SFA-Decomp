/*
 * explodeplan (DLL 0x269, object type 0x0) - a static placed prop that is
 * removed from the world by a game bit. The placement stores a removal
 * game bit at +0x1E and a packed rotX byte at +0x18.
 *
 * explodeplan_init applies the rotation and, if the removal bit is already
 * set, hides the model and disables its hit volumes. explodeplan_update
 * re-tests the bit every frame and toggles the hidden flag / hit-detection
 * state so the prop appears or disappears the moment the bit changes.
 * Render is a plain model draw at a fixed scale (lbl_803E69D0).
 */
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/dll/dll_0269_explodeplan.h"
#include "main/object_descriptor.h"


int explodeplan_getExtraSize(void)
{
    return sizeof(ExplodePlanState);
}

int explodeplan_getObjectTypeId(void)
{
    return 0;
}

void explodeplan_free(void)
{
}

void explodeplan_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    f32 scale = 1.0f;

    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, scale);
    }
}

void explodeplan_hitDetect(void)
{
}

void explodeplan_update(GameObject* obj)
{
    ExplodePlanPlacement* placement = (ExplodePlanPlacement*)obj->anim.placementData;
    if (mainGetBit(placement->removeGameBit) != 0)
    {
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        ObjHits_DisableObject(obj);
    }
    else
    {
        obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        ObjHits_EnableObject(obj);
    }
}

void explodeplan_init(GameObject* obj, ExplodePlanPlacement* placement)
{
    ObjHits_EnableObject(obj);
    if (mainGetBit(placement->removeGameBit) != 0)
    {
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        ObjHits_DisableObject(obj);
    }
    obj->anim.rotX = (s16)(placement->rotX << 8);
}

void explodeplan_release(void)
{
}

void explodeplan_initialise(void)
{
}

ObjectDescriptor gExplodePlanObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)explodeplan_initialise,
    (ObjectDescriptorCallback)explodeplan_release,
    0,
    (ObjectDescriptorCallback)explodeplan_init,
    (ObjectDescriptorCallback)explodeplan_update,
    (ObjectDescriptorCallback)explodeplan_hitDetect,
    (ObjectDescriptorCallback)explodeplan_render,
    (ObjectDescriptorCallback)explodeplan_free,
    (ObjectDescriptorCallback)explodeplan_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)explodeplan_getExtraSize,
};
