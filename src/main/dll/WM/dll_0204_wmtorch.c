/*
 * wmtorch (DLL 0x0204) - the lightable torch at Krazoa Palace.
 *
 * init attaches the flame effect for the placement's torch type (two
 * variants from resource 0x69, the third from 0x63) and scales the
 * model; update spins type-2 torches and runs a proximity sound loop
 * around the player; free releases the flame and the optional linked
 * object.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/dll_0063_dll63func0.h"
#include "main/dll/dll_0069_dll69func0.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/obj_placement.h"
#include "main/resource.h"
#include "main/vecmath.h"
#include "main/dll/WM/dll_0204_wmtorch.h"
#include "main/object_descriptor.h"

#define WMTORCH_OBJFLAG_HITDETECT_DISABLED 0x2000

extern f32 lbl_803E5DEC; /* 90.0: motionRate default */
extern f32 lbl_803E5DF0; /* flame param */
extern f32 lbl_803E5DF4; /* model scale factor */
extern f32 lbl_803E5DF8; /* model scale factor */
extern f32 lbl_803E5DE8; /* sound-loop radius */

int wmtorch_getExtraSize(void)
{
    return sizeof(WmTorchState);
}
int wmtorch_getObjectTypeId(void)
{
    return 0x1;
}

void wmtorch_free(GameObject* obj, int mode)
{
    int state = *(int*)&(obj)->extra;
    if (mode == 0 && ((WmTorchState*)state)->linkedObj != 0)
    {
        Obj_FreeObject(((WmTorchState*)state)->linkedObj);
    }
    (*gModgfxInterface)->detachSource((void*)obj);
    (*gExpgfxInterface)->freeSource((int)obj);
}

void wmtorch_render(int* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    if (visible == 0)
        return;
}

void wmtorch_hitDetect(void)
{
}

void wmtorch_update(GameObject* obj)
{
    int state = *(int*)&(obj)->extra;
    if (((WmTorchState*)state)->torchType == 2)
    {
        (obj)->anim.rotX += 0x32;
    }
    if (Vec_distance(&((GameObject*)Obj_GetPlayerObject())->anim.worldPosX, &(obj)->anim.worldPosX) < lbl_803E5DE8)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_mushdizzylp12);
    }
    else
    {
        Sfx_StopObjectChannel((int)obj, 0x40);
    }
}

void wmtorch_init(u8* obj, u8* params)
{
    WmTorchState* state;
    void* res;
    f32 flameParams[5]; /* flame params; only [4] is set, the rest raw on purpose */

    state = ((GameObject*)obj)->extra;
    if (((WmTorchPlacement*)params)->motionRate != 0)
    {
        state->motionRate = (f32)(s32)((WmTorchPlacement*)params)->motionRate;
    }
    else
    {
        state->motionRate = lbl_803E5DEC;
    }
    if (((WmTorchPlacement*)params)->colorIdx != 0)
    {
        state->colorIdx = ((WmTorchPlacement*)params)->colorIdx;
    }
    else
    {
        state->colorIdx = 0x8c;
    }
    state->torchType = ((WmTorchPlacement*)params)->torchType;
    flameParams[4] = lbl_803E5DF0;
    if (state->torchType == 0)
    {
        res = Resource_Acquire(0x69, 1);
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * lbl_803E5DF4;
        (*(Dll69Interface**)res)->spawn(obj, 1, flameParams, 0x10004, -1, NULL);
    }
    else if (state->torchType == 0x7f)
    {
        res = Resource_Acquire(0x69, 1);
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * lbl_803E5DF4;
        (*(Dll69Interface**)res)->spawn(obj, 2, flameParams, 0x10004, -1, NULL);
    }
    else
    {
        res = Resource_Acquire(0x63, 1);
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * lbl_803E5DF4;
        (*(Dll63Interface**)res)->spawn(obj, 2, flameParams, 0x10004, -1, NULL);
    }
    ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * lbl_803E5DF8;
    Resource_Release(res);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | WMTORCH_OBJFLAG_HITDETECT_DISABLED);
}

void wmtorch_release(void)
{
}

void wmtorch_initialise(void)
{
}

ObjectDescriptor gWM_TorchObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)wmtorch_initialise,
    (ObjectDescriptorCallback)wmtorch_release,
    0,
    (ObjectDescriptorCallback)wmtorch_init,
    (ObjectDescriptorCallback)wmtorch_update,
    (ObjectDescriptorCallback)wmtorch_hitDetect,
    (ObjectDescriptorCallback)wmtorch_render,
    (ObjectDescriptorCallback)wmtorch_free,
    (ObjectDescriptorCallback)wmtorch_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)wmtorch_getExtraSize,
};

u32 lbl_80328AD8[12] = {0};
