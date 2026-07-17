/*
 * dimbossgut (DLL 0x1E1) - the DIM boss gut cavity object (interior mesh).
 * Advances the gut's idle animation each frame and renders it.
 * The animEventCallback is wired to DIM_BossGut_SeqFn to clear the
 * hit-volume pair and suppress sequence events.
 */
#include "main/dll/DIM/dll_01E1_dimbossgut.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/object_render.h"
#include "main/frame_timing.h"

extern f32 lbl_803E4C80;
extern f32 lbl_803E4C84;
extern f32 lbl_803E4C88;

int DIM_BossGut_SeqFn(int obj, int runtime, ObjAnimUpdateState* animUpdate)
{
    animUpdate->hitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;
    return 0;
}

int DIM_BossGut_getExtraSize(void)
{
    return 0x0;
}
int DIM_BossGut_getObjectTypeId(void)
{
    return 0x0;
}

void DIM_BossGut_free(void)
{
}

void DIM_BossGut_render(int obj, u32 p2, u32 p3, u32 p4, u32 p5, char shouldRender)
{
    int visible;

    visible = shouldRender;
    if (visible != 0)
    {
        ObjAnim_AdvanceCurrentMove((int)obj, lbl_803E4C80, timeDelta, NULL);
        objRenderModelAndHitVolumesFwdDoubleLegacy(obj, p2, p3, p4, p5, (double)lbl_803E4C84);
    }
}

void DIM_BossGut_hitDetect(void)
{
}

void DIM_BossGut_update(void)
{
}

void DIM_BossGut_init(void* obj)
{
    int objArg;

    objSetSlot((GameObject*)obj, 0x5a);
    ((GameObject*)obj)->animEventCallback = DIM_BossGut_SeqFn;
    objArg = (int)obj;
    ObjAnim_SetCurrentMove(objArg, 0, lbl_803E4C88, 0);
    ObjAnim_AdvanceCurrentMove(objArg, (double)lbl_803E4C80, (double)timeDelta, NULL);
}

void DIM_BossGut_release(void)
{
}

void DIM_BossGut_initialise(void)
{
}

ObjectDescriptor gDIM_BossGutObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DIM_BossGut_initialise,
    (ObjectDescriptorCallback)DIM_BossGut_release,
    0,
    (ObjectDescriptorCallback)DIM_BossGut_init,
    (ObjectDescriptorCallback)DIM_BossGut_update,
    (ObjectDescriptorCallback)DIM_BossGut_hitDetect,
    (ObjectDescriptorCallback)DIM_BossGut_render,
    (ObjectDescriptorCallback)DIM_BossGut_free,
    (ObjectDescriptorCallback)DIM_BossGut_getObjectTypeId,
    DIM_BossGut_getExtraSize,
};
