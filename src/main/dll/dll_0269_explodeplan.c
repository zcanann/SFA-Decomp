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

__declspec(section ".sdata2") f32 lbl_803E69D0 = 1.0f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E69D4 = 0.0f;
#pragma explicit_zero_data off

#define EXPLODEPLAN_OBJECT_TYPE_ID 0x0

int explodeplan_getExtraSize(void)
{
    return sizeof(ExplodePlanState);
}

int explodeplan_getObjectTypeId(void)
{
    return EXPLODEPLAN_OBJECT_TYPE_ID;
}

void explodeplan_free(void)
{
}

void explodeplan_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)lbl_803E69D0);
    }
}

void explodeplan_hitDetect(void)
{
}

void explodeplan_update(GameObject* obj)
{
    ExplodePlanPlacement* placement = *(ExplodePlanPlacement**)&(obj)->anim.placementData;
    if (mainGetBit(placement->removeGameBit) != 0)
    {
        (obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        ObjHits_DisableObject((int)obj);
    }
    else
    {
        (obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        ObjHits_EnableObject((int)obj);
    }
}

#pragma opt_common_subs off
void explodeplan_init(GameObject* obj, char* arg)
{
    ExplodePlanPlacement* def = (ExplodePlanPlacement*)arg;
    ObjHits_EnableObject((int)obj);
    if (mainGetBit(def->removeGameBit) != 0)
    {
        (obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        ObjHits_DisableObject((int)obj);
    }
    (obj)->anim.rotX = (s16)(def->rotXByte << 8);
}
#pragma opt_common_subs reset

void explodeplan_release(void)
{
}

void explodeplan_initialise(void)
{
}
