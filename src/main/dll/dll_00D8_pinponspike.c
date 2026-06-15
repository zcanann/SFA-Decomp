#include "main/dll/MMP/MMP_asteroid.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/xyzanimator.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/objhits.h"

extern undefined4 FUN_800067e8();
extern uint FUN_8007f6c8();
extern undefined4 FUN_8007f718();
extern undefined4 FUN_8008112c();

extern f32 lbl_803E3DF4;
extern f32 lbl_803E3DF8;

extern void Sfx_PlayFromObject(int obj, int sfxId);

void pollenfragment_init(int obj, int config);

extern void kaldachompspit_free(void);
extern void kaldachompspit_update(void);
extern int kaldachompspit_getObjectTypeId(void);
extern int kaldachompspit_getExtraSize(void);
extern f32 timeDelta;
extern f32 lbl_803E3110;
extern f32 lbl_803E3114;
extern f32 lbl_803E3118;
extern f32 lbl_803E311C;
extern f32 lbl_803E3120;
extern f32 lbl_803E3124;
extern f32 lbl_803E3128;
extern f32 lbl_803E312C;
extern f32 sqrtf(f32 x);
extern int getAngle(f32 a, f32 b);
extern void objMove(int obj, f32 x, f32 y, f32 z);
extern void* Obj_GetPlayerObject(void);
extern void* getTrickyObject(void);

void FUN_8016b228(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  uint param_9)
{
    uint uVar1;
    int iVar2;
    int iVar3;
    ObjHitsPriorityState* hitState;
    int auStack_18[4];

    iVar3 = *(int*)&((GameObject*)param_9)->extra;
    hitState = (ObjHitsPriorityState*)((GameObject*)param_9)->anim.hitReactState;
    uVar1 = FUN_8007f6c8((float*)(iVar3 + 0x20));
    if (uVar1 == 0)
    {
        iVar2 = ObjHits_GetPriorityHit(param_9, auStack_18, (int*)0x0, (uint*)0x0);
        if ((iVar2 == 0xe) || (iVar2 == 0xf))
        {
            if (*(short*)(((XyzAnimatorState*)iVar3)->unk1C + 4) != -1)
            {
                FUN_8008112c((double)lbl_803E3DF4, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             param_9, 0, 1, 0, 1, 0, 1, 0);
                FUN_800067e8(param_9, *(ushort*)(((XyzAnimatorState*)iVar3)->unk1C + 4), 3);
            }
            ObjHits_DisableObject(param_9);
            FUN_8007f718((float*)(iVar3 + 0x20), 0x78);
        }
        if (hitState->contactFlags != 0)
        {
            ObjHits_DisableObject(param_9);
            *(float*)&((XyzAnimatorState*)iVar3)->unk8 = lbl_803E3DF8;
            if (*(short*)(((XyzAnimatorState*)iVar3)->unk1C + 4) != -1)
            {
                FUN_8008112c((double)lbl_803E3DF4, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             param_9, 0, 1, 0, 1, 0, 1, 0);
                FUN_800067e8(param_9, *(ushort*)(((XyzAnimatorState*)iVar3)->unk1C + 4), 3);
            }
            FUN_8007f718((float*)(iVar3 + 0x20), 0x78);
        }
    }
    return;
}

void pinponspike_render(void)
{
}

void pinponspike_hitDetect(void)
{
}

void pinponspike_release(void)
{
}

void pinponspike_initialise(void)
{
}

void pollen_release(void);

void pollen_initialise(void);

void pollenfragment_release(void);

void pollenfragment_initialise(void);

void pinponspike_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void pollen_free(int obj);

void pinponspike_init(int obj)
{
    ((GameObject*)obj)->unkF4 = 0;
    ObjHits_DisableObject(obj);
    ((GameObject*)obj)->anim.alpha = 0xff;
    Sfx_PlayFromObject(obj, SFXsc_attack02);
    ((GameObject*)obj)->objectFlags |= 0x6000;
}

void pollen_hitDetect(int obj);

void pollenfragment_free(int obj);

int pinponspike_getExtraSize(void) { return 0x0; }
int pinponspike_getObjectTypeId(void) { return 0x0; }
int pollen_getExtraSize(void);
int pollen_getObjectTypeId(void);
int pollenfragment_getExtraSize(void);
int pollenfragment_getObjectTypeId(void);

void pollen_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

ObjectDescriptor gKaldaChompSpitObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)kaldachompspit_initialise,
    (ObjectDescriptorCallback)kaldachompspit_release,
    0,
    (ObjectDescriptorCallback)kaldachompspit_init,
    (ObjectDescriptorCallback)kaldachompspit_update,
    (ObjectDescriptorCallback)kaldachompspit_hitDetect,
    (ObjectDescriptorCallback)kaldachompspit_render,
    (ObjectDescriptorCallback)kaldachompspit_free,
    (ObjectDescriptorCallback)kaldachompspit_getObjectTypeId,
    kaldachompspit_getExtraSize,
};

ObjectDescriptor gPinPonSpikeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)pinponspike_initialise,
    (ObjectDescriptorCallback)pinponspike_release,
    0,
    (ObjectDescriptorCallback)pinponspike_init,
    (ObjectDescriptorCallback)pinponspike_update,
    (ObjectDescriptorCallback)pinponspike_hitDetect,
    (ObjectDescriptorCallback)pinponspike_render,
    (ObjectDescriptorCallback)pinponspike_free,
    (ObjectDescriptorCallback)pinponspike_getObjectTypeId,
    pinponspike_getExtraSize,
};

ObjectDescriptor gPollenObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)pollen_initialise,
    (ObjectDescriptorCallback)pollen_release,
    0,
    (ObjectDescriptorCallback)pollen_init,
    (ObjectDescriptorCallback)pollen_update,
    (ObjectDescriptorCallback)pollen_hitDetect,
    (ObjectDescriptorCallback)pollen_render,
    (ObjectDescriptorCallback)pollen_free,
    (ObjectDescriptorCallback)pollen_getObjectTypeId,
    pollen_getExtraSize,
};

PollenFragmentConfig lbl_80320538 = {
    0x0000,
    0x049F,
    0x00B9,
    0x04BA,
    0x04BA,
    -1,
    0.2f,
    0x0000,
    0xC000,
};

PollenFragmentConfig lbl_8032054C = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    0x068F,
    0.4f,
    0x0026,
    0x7000,
};

PollenFragmentConfig lbl_80320560 = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    0x068F,
    0.4f,
    0x0026,
    0x2000,
};

PollenFragmentConfig lbl_80320574 = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    -1,
    0.2f,
    0x0000,
    0x2000,
};

PollenFragmentConfig lbl_80320588 = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    0x068F,
    0.4f,
    0x0026,
    0x3000,
};

PollenFragmentConfig* lbl_8032059C[] = {
    &lbl_80320538,
    &lbl_8032054C,
    &lbl_80320560,
    &lbl_80320574,
    &lbl_80320588,
};

void pollenfragment_render(int* obj, int p2, int p3, int p4, int p5);

ObjectDescriptor gPollenFragmentObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)pollenfragment_initialise,
    (ObjectDescriptorCallback)pollenfragment_release,
    0,
    (ObjectDescriptorCallback)pollenfragment_init,
    (ObjectDescriptorCallback)pollenfragment_update,
    (ObjectDescriptorCallback)pollenfragment_hitDetect,
    (ObjectDescriptorCallback)pollenfragment_render,
    (ObjectDescriptorCallback)pollenfragment_free,
    (ObjectDescriptorCallback)pollenfragment_getObjectTypeId,
    pollenfragment_getExtraSize,
};

int fn_80169EF4(f32 speed, f32 grav, f32* from, f32* to, u8 flag)
{
    f32 a;
    f32 dist;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 t;
    f32 disc;

    dx = from[0] - to[0];
    dz = from[2] - to[2];
    dist = sqrtf(dx * dx + dz * dz);
    dy = from[1] - to[1];
    dist = dist * lbl_803E3110;
    a = grav * (lbl_803E3114 * grav);
    grav = -(grav * dy) - (speed = speed * speed);
    disc = grav * grav - (lbl_803E3118 * a) * (dy * dy + dist * dist);
    if (disc >= lbl_803E311C)
    {
        if (flag)
        {
            t = (lbl_803E3120 * (-grav + sqrtf(disc))) / a;
        }
        else
        {
            t = (lbl_803E3120 * (-grav - sqrtf(disc))) / a;
        }
        t = sqrtf(t);
        a = dist / t;
        return getAngle(sqrtf(-(a * a - speed)), a);
    }
    return 0x2000;
}

void pinponspike_update(int obj)
{
    f32 vx;
    f32 vy;
    f32 vz;

    if (((GameObject*)obj)->unkF4 > 0)
    {
        ((GameObject*)obj)->unkF4 = (int)((f32)((GameObject*)obj)->unkF4 - timeDelta);
        if (((GameObject*)obj)->unkF4 <= 0)
        {
            Obj_FreeObject(obj);
            return;
        }
    }
    if (((GameObject*)obj)->anim.alpha != 0)
    {
        vx = ((GameObject*)obj)->anim.velocityX * timeDelta;
        vy = ((GameObject*)obj)->anim.velocityY * timeDelta;
        vz = ((GameObject*)obj)->anim.velocityZ * timeDelta;
        objMove(obj, vx, vy, vz);
        ((GameObject*)obj)->anim.velocityY += lbl_803E3124 * timeDelta;
        if (((GameObject*)obj)->anim.velocityY < *(f32*)&lbl_803E3128)
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E3128;
        }
        ((GameObject*)obj)->anim.rotX = getAngle(vx, vz) - 0x8000;
        ((GameObject*)obj)->anim.rotY = 0x4000 - getAngle(sqrtf(vx * vx + vz * vz), vy);
        ObjHits_SetHitVolumeSlot(obj, 10, 1, 0);
        ObjHits_EnableObject(obj);
        if (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject != 0 &&
            (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject == (int)Obj_GetPlayerObject() ||
             ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject == (int)getTrickyObject()))
        {
            int i;
            ((GameObject*)obj)->anim.alpha = 0;
            ((GameObject*)obj)->unkF4 = 0x78;
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
            for (i = 0; i < 0x19; i++)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x715, NULL, 1, -1, &i);
            }
            Sfx_PlayFromObject(obj, 0x279);
        }
        else if (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->contactFlags != 0)
        {
            int i;
            ((GameObject*)obj)->anim.alpha = 0;
            ((GameObject*)obj)->unkF4 = 0x78;
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
            for (i = 0; i < 0x19; i++)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x715, NULL, 1, -1, &i);
            }
            Sfx_PlayFromObject(obj, 0x279);
        }
        else if (((GameObject*)obj)->anim.localPosY < lbl_803E312C)
        {
            Obj_FreeObject(obj);
        }
    }
}

void pollen_update(int obj);

void pollenfragment_hitDetect(int obj);

void pollenfragment_update(int obj);
