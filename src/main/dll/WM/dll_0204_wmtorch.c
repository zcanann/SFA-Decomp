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
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/resource.h"
#include "main/engine_shared.h"

#define WMTORCH_OBJFLAG_HITDETECT_DISABLED 0x2000

typedef struct WmTorchPlacement
{
    ObjPlacement base;
    u8 pad18;
    u8 torchType; /* 0x19: 0 / 0x7F = resource-0x69 flames, else 0x63 */
    s16 unk1A;    /* 0x1A: state value, default 90.0 when 0 */
    s16 unk1C;    /* 0x1C: state value, default 0x8C when 0 */
} WmTorchPlacement;

STATIC_ASSERT(offsetof(WmTorchPlacement, torchType) == 0x19);
STATIC_ASSERT(offsetof(WmTorchPlacement, unk1C) == 0x1C);

typedef struct WmTorchState
{
    void* linkedObj;
    f32 unk04;    /* from placement unk1A */
    u8 pad08[2];
    s16 unk0A;    /* from placement unk1C */
    u8 torchType; /* placement torchType: 0 / 0x7F / other */
    u8 pad0D[3];
} WmTorchState;

STATIC_ASSERT(sizeof(WmTorchState) == 0x10);

/* slot 1 of the acquired effect resource's vtable: attach the flame */
typedef void (*WmTorchAttachFlameFn)(u8* obj, int variant, f32* params, int flags, int p5, int p6);

extern ModgfxInterface** gModgfxInterface;
extern f32 lbl_803E5DEC; /* 90.0: unk04 default */
extern f32 lbl_803E5DF0; /* flame param */
extern f32 lbl_803E5DF4; /* model scale factor */
extern f32 lbl_803E5DF8; /* model scale factor */
extern f32 Vec_distance(f32* a, f32* b);
extern f32 lbl_803E5DE8; /* sound-loop radius */
extern void Obj_FreeObject(u8* obj);

int wmtorch_getExtraSize(void) { return sizeof(WmTorchState); }
int wmtorch_getObjectTypeId(void) { return 0x1; }

void wmtorch_free(int obj, int mode)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    if (mode == 0 && ((WmTorchState*)state)->linkedObj != 0)
    {
        Obj_FreeObject(((WmTorchState*)state)->linkedObj);
    }
    (*gModgfxInterface)->detachSource((void*)obj);
    (*gExpgfxInterface)->freeSource(obj);
}

void wmtorch_render(int* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    if (visible == 0) return;
}

void wmtorch_hitDetect(void)
{
}

void wmtorch_update(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    if (((WmTorchState*)state)->torchType == 2)
    {
        ((GameObject*)obj)->anim.rotX += 0x32;
    }
    if (Vec_distance(&((GameObject*)Obj_GetPlayerObject())->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX) <
        lbl_803E5DE8)
    {
        Sfx_PlayFromObject(obj, SFXmn_eggylaugh216);
    }
    else
    {
        Sfx_StopObjectChannel(obj, 0x40);
    }
}

void wmtorch_init(u8* obj, u8* params)
{
    WmTorchState* sub;
    void* res;
    f32 v[5]; /* flame params; only [4] is set, the rest raw on purpose */

    sub = ((GameObject*)obj)->extra;
    if (((WmTorchPlacement*)params)->unk1A != 0)
    {
        sub->unk04 = (f32)(s32)((WmTorchPlacement*)params)->unk1A;
    }
    else
    {
        sub->unk04 = lbl_803E5DEC;
    }
    if (((WmTorchPlacement*)params)->unk1C != 0)
    {
        sub->unk0A = ((WmTorchPlacement*)params)->unk1C;
    }
    else
    {
        sub->unk0A = 0x8c;
    }
    sub->torchType = ((WmTorchPlacement*)params)->torchType;
    v[4] = lbl_803E5DF0;
    if (sub->torchType == 0)
    {
        res = Resource_Acquire(0x69, 1);
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * lbl_803E5DF4;
        ((WmTorchAttachFlameFn)((void**)*(int*)res)[1])(obj, 1, v, 0x10004, -1, 0);
    }
    else if (sub->torchType == 0x7f)
    {
        res = Resource_Acquire(0x69, 1);
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * lbl_803E5DF4;
        ((WmTorchAttachFlameFn)((void**)*(int*)res)[1])(obj, 2, v, 0x10004, -1, 0);
    }
    else
    {
        res = Resource_Acquire(0x63, 1);
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * lbl_803E5DF4;
        ((WmTorchAttachFlameFn)((void**)*(int*)res)[1])(obj, 2, v, 0x10004, -1, 0);
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
