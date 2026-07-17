/*
 * felevcontrol (DLL 0x142) - floating elevator control object for the
 * CloudRunner Fortress / Dinosaur Planet elevator sequences.
 *
 * The render function passes lbl_803E56B8 (the elevator's render scale /
 * distance threshold) to the common objRenderModelAndHitVolumes.
 *
 */
#include "main/dll/DB/DBrockfall.h"
#include "main/game_object.h"
#include "main/object_render_legacy.h"

extern f32 lbl_803E56B8;

int FElevControl_getExtraSize(void)
{
    return 0x0;
}
int FElevControl_getObjectTypeId(void)
{
    return 0x0;
}

void FElevControl_free(void)
{
}

void FElevControl_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E56B8);
}

void FElevControl_hitDetect(void)
{
}

void FElevControl_update(void)
{
}

void FElevControl_init(int obj)
{
    ObjMsg_AllocQueue(obj, 0x2);
}

void FElevControl_release(void)
{
}

void FElevControl_initialise(void)
{
}

ObjectDescriptor gFElevControlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)FElevControl_initialise,
    (ObjectDescriptorCallback)FElevControl_release,
    0,
    (ObjectDescriptorCallback)FElevControl_init,
    (ObjectDescriptorCallback)FElevControl_update,
    (ObjectDescriptorCallback)FElevControl_hitDetect,
    (ObjectDescriptorCallback)FElevControl_render,
    (ObjectDescriptorCallback)FElevControl_free,
    (ObjectDescriptorCallback)FElevControl_getObjectTypeId,
    FElevControl_getExtraSize,
};
