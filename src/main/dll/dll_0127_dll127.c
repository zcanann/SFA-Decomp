/*
 * DLL 0x0127 (object type id 0x13). A simple swaying/scaling prop:
 *  - init reads its placement bytes for sway magnitude, model bank and
 *    initial yaw, then scales rootMotion (and the shadow model) by a
 *    sway factor derived from the placement byte.
 *  - render forwards a fixed scale to objRenderFn_8003b8f4.
 *  - update runs a hit-react cooldown: while the object has a hit-react
 *    state, a 100-frame timer (obj+0xF8) counts down by framesThisStep
 *    and is re-armed whenever the hit-react flags carry bit 8.
 * TU: 0x8018CD64-0x8018CEE4.
 */
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objhits.h"
#include "main/dll/VF/vf_shared.h"
extern f32 lbl_803E3D60; /* render scale */
extern f32 lbl_803E3D64; /* minimum sway magnitude */
extern f32 lbl_803E3D68; /* sway -> scale multiplier */

typedef struct Dll127Placement
{
    ObjPlacement head;
    u8 bankIndex; /* 0x18 */
    u8 swayMag;   /* 0x19 */
    u8 yawBits;   /* 0x1a */
} Dll127Placement;

STATIC_ASSERT(offsetof(Dll127Placement, bankIndex) == 0x18);
STATIC_ASSERT(offsetof(Dll127Placement, swayMag) == 0x19);
STATIC_ASSERT(offsetof(Dll127Placement, yawBits) == 0x1a);

void dll_127_free_nop(void)
{
}

void dll_127_hitDetect_nop(void)
{
}

int dll_127_getExtraSize_ret_0(void) { return 0x0; }
int dll_127_getObjectTypeId(void) { return 0x13; }

void dll_127_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 isVisible = visible;
    if (isVisible != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E3D60);
}

void dll_127_update(int obj)
{
    int pairResponseApplied;
    ObjHitsPriorityState* hitState;

    if (((GameObject*)obj)->anim.hitReactState == 0)
    {
        return;
    }
    if (*(short*)(obj + 0xf8) > 0)
    {
        *(short*)(obj + 0xf8) -= framesThisStep;
    }
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    pairResponseApplied = hitState->flags & OBJHITS_PRIORITY_STATE_PAIR_RESPONSE_APPLIED;
    if (pairResponseApplied == 0)
    {
        return;
    }
    if (*(short*)(obj + 0xf8) > 0)
    {
        return;
    }
    *(short*)(obj + 0xf8) = 100;
}

void dll_127_init(short* obj, int def)
{
    Dll127Placement* placement;
    ObjAnimComponent* objAnim;
    float scale;
    u32 yawBits;
    u8 swayMag;

    placement = (Dll127Placement*)def;
    objAnim = (ObjAnimComponent*)obj;
    objAnim->flags |= 2;
    swayMag = placement->swayMag;
    scale = (f32)(int)swayMag;
    if ((f32)(int)swayMag < lbl_803E3D64)
    {
        scale = *(f32*)&lbl_803E3D64;
    }
    scale = scale * lbl_803E3D68;
    objAnim->rootMotionScale = objAnim->modelInstance->rootMotionScaleBase * scale;
    if (objAnim->modelState != NULL)
    {
        *(float*)objAnim->modelState = *(float*)objAnim->modelInstance * scale;
    }
    objAnim->bankIndex = placement->bankIndex;
    yawBits = placement->yawBits & 0x3f;
    objAnim->rotX = (short)(yawBits << 10);
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    ((GameObject*)obj)->unkF4 = 0;
    ((GameObject*)obj)->unkF8 = 0;
}

void dll_127_release_nop(void)
{
}

void dll_127_initialise_nop(void)
{
}
