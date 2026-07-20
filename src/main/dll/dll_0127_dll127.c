/*
 * DLL 0x0127 (object type id 0x13). A simple swaying/scaling prop:
 *  - init reads its placement bytes for sway magnitude, model bank and
 *    initial yaw, then scales rootMotion (and the shadow model) by a
 *    sway factor derived from the placement byte.
 *  - render forwards a fixed scale to objRenderModelAndHitVolumes.
 *  - update runs a hit-react cooldown: while the object has a hit-react
 *    state, a 100-frame timer (obj+0xF8) counts down by framesThisStep
 *    and is re-armed whenever the hit-react flags carry bit 8.
 * TU: 0x8018CD64-0x8018CEE4.
 */
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objhits.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/object_descriptor.h"
#include "main/dll/dll_0127_dll127.h"

int dll_127_getExtraSize_ret_0(void)
{
    return 0x0;
}
int dll_127_getObjectTypeId(void)
{
    return 0x13;
}

void dll_127_free_nop(void)
{
}

void dll_127_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 isVisible = visible;
    if (isVisible != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void dll_127_hitDetect_nop(void)
{
}

void dll_127_update(GameObject* obj)
{
    int pairResponseApplied;
    ObjHitsPriorityState* hitState;

    if (obj->anim.hitReactState == 0)
    {
        return;
    }
    if (*(s16*)&obj->userData2 > 0)
    {
        *(s16*)&obj->userData2 -= framesThisStep;
    }
    hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    pairResponseApplied = hitState->flags & OBJHITS_PRIORITY_STATE_PAIR_RESPONSE_APPLIED;
    if (pairResponseApplied == 0)
    {
        return;
    }
    if (*(s16*)&obj->userData2 > 0)
    {
        return;
    }
    *(s16*)&obj->userData2 = 100;
}

void dll_127_init(GameObject* obj, Dll127Setup* setup)
{
    ObjAnimComponent* objAnim;
    f32 scale;
    u32 yawBits;
    u8 swayMagnitude;

    objAnim = &obj->anim;
    objAnim->flags |= 2;
    swayMagnitude = setup->swayMagnitude;
    scale = (f32)(int)swayMagnitude;
    if ((f32)(int)swayMagnitude < 10.0f)
    {
        scale = 10.0f;
    }
    scale *= 0.015625f;
    objAnim->rootMotionScale = objAnim->modelInstance->rootMotionScaleBase * scale;
    if (objAnim->modelState != NULL)
    {
        objAnim->modelState->shadowScale = objAnim->modelInstance->shadowScaleBase * scale;
    }
    objAnim->bankIndex = setup->bankIndex;
    yawBits = setup->yawBits & 0x3f;
    objAnim->rotX = (s16)(yawBits << 10);
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    obj->userData1 = 0;
    obj->userData2 = 0;
}

void dll_127_release_nop(void)
{
}

void dll_127_initialise_nop(void)
{
}

ObjectDescriptor lbl_80321E58 = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_127_initialise_nop, (ObjectDescriptorCallback)dll_127_release_nop, 0,
    (ObjectDescriptorCallback)dll_127_init, (ObjectDescriptorCallback)dll_127_update,
    (ObjectDescriptorCallback)dll_127_hitDetect_nop, (ObjectDescriptorCallback)dll_127_render,
    (ObjectDescriptorCallback)dll_127_free_nop, (ObjectDescriptorCallback)dll_127_getObjectTypeId,
    dll_127_getExtraSize_ret_0,
};
