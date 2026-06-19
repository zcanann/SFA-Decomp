/*
 * dimbossgut (DLL 0x1E1) - the DIM boss gut cavity object (interior mesh).
 * Advances the gut's idle animation each frame and renders it.
 * The animEventCallback is wired to DIMbossgut_updateState to clear the
 * hit-volume pair and suppress sequence events.
 */
#include "main/dll/DIM/dll_01E1_dimbossgut.h"
#include "main/game_object.h"

extern void objSetSlot(void* obj, int resourceId);
extern void objRenderFn_8003b8f4(int obj, u32 param_2, u32 param_3,
                                 u32 param_4, u32 param_5, double scale);

extern f32 timeDelta;
extern f32 lbl_803E4C80;
extern f32 lbl_803E4C84;
extern f32 lbl_803E4C88;

int DIMbossgut_updateState(int obj, int runtime, ObjAnimUpdateState* animUpdate)
{
    animUpdate->hitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;
    return 0;
}

int DIMbossgut_getExtraSize(void) { return 0x0; }
int DIMbossgut_getObjectTypeId(void) { return 0x0; }

void DIMbossgut_free(void)
{
}

void DIMbossgut_render(int obj, u32 p2, u32 p3, u32 p4,
                       u32 p5, char shouldRender)
{
    int visible;

    visible = shouldRender;
    if (visible != 0)
    {
        ObjAnim_AdvanceCurrentMove(lbl_803E4C80, timeDelta, obj, NULL);
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E4C84);
    }
}

void DIMbossgut_hitDetect(void)
{
}

void DIMbossgut_update(void)
{
}

void DIMbossgut_init(void* obj)
{
    int objArg;

    objSetSlot(obj, 0x5a);
    ((GameObject*)obj)->animEventCallback = DIMbossgut_updateState;
    objArg = (int)obj;
    ObjAnim_SetCurrentMove(objArg, 0, lbl_803E4C88, 0);
    ((ObjAnimAdvanceObjectFirstFn)ObjAnim_AdvanceCurrentMove)
        (objArg, (double)lbl_803E4C80, (double)timeDelta, NULL);
}

void DIMbossgut_release(void)
{
}

void DIMbossgut_initialise(void)
{
}

ObjectDescriptor gDIM_BossGutObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DIMbossgut_initialise,
    (ObjectDescriptorCallback)DIMbossgut_release,
    0,
    (ObjectDescriptorCallback)DIMbossgut_init,
    (ObjectDescriptorCallback)DIMbossgut_update,
    (ObjectDescriptorCallback)DIMbossgut_hitDetect,
    (ObjectDescriptorCallback)DIMbossgut_render,
    (ObjectDescriptorCallback)DIMbossgut_free,
    (ObjectDescriptorCallback)DIMbossgut_getObjectTypeId,
    DIMbossgut_getExtraSize,
};
