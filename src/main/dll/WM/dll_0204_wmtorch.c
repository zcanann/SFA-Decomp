/*
 * wmtorch (DLL 0x0204) - the lightable torch at Krazoa Palace.
 *
 * init attaches the flame effect for the placement's torch type (two
 * variants from resource 0x69, the third from 0x63) and scales the
 * model; update spins type-2 torches and runs a proximity sound loop
 * around the player; free releases the flame and the optional linked
 * object.
 */
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx.h"
#include "main/dll_000A_expgfx.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/obj_placement.h"
#include "main/resource.h"
#include "main/vecmath.h"
#include "main/dll/WM/dll_0204_wmtorch.h"

/* slot 1 of the acquired effect resource's vtable: attach the flame */
typedef void (*WmTorchAttachFlameFn)(u8* obj, int variant, f32* params, int flags, int p5, int p6);

#define WMTORCH_OBJFLAG_HITDETECT_DISABLED 0x2000

extern f32 lbl_803E5DEC; /* 90.0: unk04 default */
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
    if (((WmTorchPlacement*)params)->unk1A != 0)
    {
        state->unk04 = (f32)(s32)((WmTorchPlacement*)params)->unk1A;
    }
    else
    {
        state->unk04 = lbl_803E5DEC;
    }
    if (((WmTorchPlacement*)params)->unk1C != 0)
    {
        state->unk0A = ((WmTorchPlacement*)params)->unk1C;
    }
    else
    {
        state->unk0A = 0x8c;
    }
    state->torchType = ((WmTorchPlacement*)params)->torchType;
    flameParams[4] = lbl_803E5DF0;
    if (state->torchType == 0)
    {
        res = Resource_Acquire(0x69, 1);
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * lbl_803E5DF4;
        ((WmTorchAttachFlameFn)((void**)*(int*)res)[1])(obj, 1, flameParams, 0x10004, -1, 0);
    }
    else if (state->torchType == 0x7f)
    {
        res = Resource_Acquire(0x69, 1);
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * lbl_803E5DF4;
        ((WmTorchAttachFlameFn)((void**)*(int*)res)[1])(obj, 2, flameParams, 0x10004, -1, 0);
    }
    else
    {
        res = Resource_Acquire(0x63, 1);
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * lbl_803E5DF4;
        ((WmTorchAttachFlameFn)((void**)*(int*)res)[1])(obj, 2, flameParams, 0x10004, -1, 0);
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
