/*
 * wmtorch (DLL 0x0204) - the lightable torch at Krazoa Palace.
 */
#include "main/audio/sfx_ids.h"
#include "main/dll/laserbeamstate_struct.h"
#include "main/dll/dll200state_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/resource.h"

STATIC_ASSERT(offsetof(LaserBeamState, beamKind) == 0x4e);

typedef struct WmTorchState
{
    void* linkedObj;
    f32 unk04;
    u8 pad08[2];
    s16 unk0A;
    u8 torchType; /* params[0x19]: 0 / 0x7f / other */
    u8 pad0D[3];
} WmTorchState;

STATIC_ASSERT(sizeof(Dll200State) == 0x28);

extern ModgfxInterface** gModgfxInterface;

extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern f32 lbl_803E5DEC;
extern f32 lbl_803E5DF0;
extern f32 lbl_803E5DF4;
extern f32 lbl_803E5DF8;
extern void* lbl_803DDC80;
extern int Obj_GetPlayerObject(void);
extern f32 Vec_distance(f32* a, f32* b);
extern f32 lbl_803E5DE8;
extern void Obj_FreeObject(void* o);
extern void ModelLightStruct_free(void* light);

void wmtorch_hitDetect(void)
{
}

void wmtorch_release(void)
{
}

void wmtorch_initialise(void)
{
}

void wmtorch_init(u8* obj, u8* params)
{
    WmTorchState* sub;
    void* res;
    f32 v[5];

    sub = ((GameObject*)obj)->extra;
    if (*(s16*)(params + 0x1a) != 0)
    {
        sub->unk04 = (f32)(s32)*(s16*)(params + 0x1a);
    }
    else
    {
        sub->unk04 = lbl_803E5DEC;
    }
    if (*(s16*)(params + 0x1c) != 0)
    {
        sub->unk0A = *(s16*)(params + 0x1c);
    }
    else
    {
        sub->unk0A = 0x8c;
    }
    sub->torchType = params[0x19];
    v[4] = lbl_803E5DF0;
    if (sub->torchType == 0)
    {
        res = Resource_Acquire(0x69, 1);
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * lbl_803E5DF4;
        ((void(*)(u8*, int, f32*, int, int, int))((void**)*(int*)res)[1])(obj, 1, v, 0x10004, -1, 0);
    }
    else if (sub->torchType == 0x7f)
    {
        res = Resource_Acquire(0x69, 1);
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * lbl_803E5DF4;
        ((void(*)(u8*, int, f32*, int, int, int))((void**)*(int*)res)[1])(obj, 2, v, 0x10004, -1, 0);
    }
    else
    {
        res = Resource_Acquire(0x63, 1);
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * lbl_803E5DF4;
        ((void(*)(u8*, int, f32*, int, int, int))((void**)*(int*)res)[1])(obj, 2, v, 0x10004, -1, 0);
    }
    ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * lbl_803E5DF8;
    Resource_Release(res);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x2000);
}

void wmtorch_render(int* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    if (visible == 0) return;
}

int wmtorch_getExtraSize(void) { return 0x10; }
int wmtorch_getObjectTypeId(void) { return 0x1; }
int lightsource_getExtraSize(void);

void wmtorch_update(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    if (((WmTorchState*)state)->torchType == 2)
    {
        *(s16*)obj += 0x32;
    }
    if (Vec_distance((f32*)(Obj_GetPlayerObject() + 0x18), &((GameObject*)obj)->anim.worldPosX) < lbl_803E5DE8)
    {
        Sfx_PlayFromObject(obj, SFXmn_eggylaugh216);
    }
    else
    {
        Sfx_StopObjectChannel(obj, 0x40);
    }
}

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


typedef struct LightSourceFlagByte
{
    u8 looped : 1;
} LightSourceFlagByte;

