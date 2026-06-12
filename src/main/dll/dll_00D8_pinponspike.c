#include "main/dll/MMP/MMP_asteroid.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/xyzanimator.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"



extern undefined4 FUN_800067e8();
extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined8 ObjHits_EnableObject();
extern void ObjHits_SetTargetMask(int obj, u8 mask);
extern int ObjHits_GetPriorityHit();
extern int ObjGroup_FindNearestObject();
extern undefined4 ObjPath_GetPointWorldPosition();
extern uint FUN_8007f6c8();
extern undefined4 FUN_8007f718();
extern undefined4 FUN_8008112c();
extern int Sfx_PlayFromObjectLimited(int obj, int sfxId, int maxCount);
extern void s16toFloat(void* timer, int duration);

typedef struct
{
    s16 unk00; /* 0x00 */
    s16 loopSfx; /* 0x02 */
    s16 explodeSfx; /* 0x04 */
    s16 unk06; /* 0x06 */
    s16 burstFx; /* 0x08 */
    s16 auraFx; /* 0x0A */
    s16 unk0C; /* 0x0C */
    s16 unk0E; /* 0x0E */
    s16 targetGroup; /* 0x10 */
    u8 noVertical : 1; /* 0x12 bit 7 */
    u8 timed : 1; /* 0x12 bit 6 */
    u8 smoothTurn : 1; /* 0x12 bit 5 */
    u8 usePath : 1; /* 0x12 bit 4 */
} PollenFragmentDef;

/* pollenfragment extra block (head; timers at 0x20/0x24 stay raw addr args). */
typedef struct PollenFragmentExtra
{
    u8 unk00[0xC];
    f32 velX;
    f32 velY;
    f32 velZ;
    u8 unk18[4];
    PollenFragmentDef* def; /* 0x1C */
} PollenFragmentExtra;


extern void storeZeroToFloatParam(void* timer);

extern EffectInterface** gPartfxInterface;
extern f32 lbl_803E3DF4;
extern f32 lbl_803E3DF8;
extern f32 lbl_803E3198;
extern f32 lbl_803E319C;

/*
 * --INFO--
 *
 * Function: kaldachompspit_render
 * EN v1.0 Address: 0x8016984C
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x80169CF8
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: kaldachompspit_init
 * EN v1.0 Address: 0x80169CC4
 * EN v1.0 Size: 552b
 * EN v1.1 Address: 0x8016A170
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void Sfx_PlayFromObject(int obj, int sfxId);



#pragma dont_inline on
void fn_8016A660(int obj);
#pragma dont_inline reset


/*
 * --INFO--
 *
 * Function: pollenfragment_init
 * EN v1.0 Address: 0x8016B0A4
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x8016ACA4
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void pollenfragment_init(int obj, int config);


/*
 * --INFO--
 *
 * Function: FUN_8016b228
 * EN v1.0 Address: 0x8016B228
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x8016AE70
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016b228(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  uint param_9)
{
    uint uVar1;
    int iVar2;
    int iVar3;
    undefined4 auStack_18[4];

    iVar3 = *(int*)&((GameObject*)param_9)->extra;
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
        if ((*(ObjHitsPriorityState**)&((GameObject*)param_9)->anim.hitReactState)->contactFlags != 0)
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


/* Trivial 4b 0-arg blr leaves. */


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

void mikabomb_hitDetect(void);

extern f32 lbl_803E313C;

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

void mikabomb_free(int obj, int mode);

/* 8b "li r3, N; blr" returners. */
int pinponspike_getExtraSize(void) { return 0x0; }
int pinponspike_getObjectTypeId(void) { return 0x0; }
int pollen_getExtraSize(void);
int pollen_getObjectTypeId(void);
int pollenfragment_getExtraSize(void);
int pollenfragment_getObjectTypeId(void);
int mikabomb_getExtraSize(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3138;
extern void objRenderFn_8003b8f4(f32);

void pollen_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void mikabomb_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

extern void kaldachompspit_free(void);
extern void kaldachompspit_update(void);
extern int kaldachompspit_getObjectTypeId(void);
extern int kaldachompspit_getExtraSize(void);

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

extern int fn_80080150(int p);
extern f32 lbl_803E3158;

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

extern f32 lbl_803E3148;

void pollen_init(int* obj);

/* ==== v1.0 recovered functions (drift additions) ==== */


typedef struct
{
    f32 x, y, z;
} XyzVec;

extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 lbl_803DBD48;
extern f32 lbl_803DBD4C;
extern f32 lbl_803E3110;
extern f32 lbl_803E3114;
extern f32 lbl_803E3118;
extern f32 lbl_803E311C;
extern f32 lbl_803E3120;
extern f32 lbl_803E3124;
extern f32 lbl_803E3128;
extern f32 lbl_803E312C;
extern f32 lbl_803E3140;
extern f32 lbl_803E315C;
extern f32 lbl_803E3160;
extern f32 lbl_803E3164;
extern f32 lbl_803E3168;
extern f32 lbl_803E316C;
extern f32 lbl_803E3170;
extern f32 lbl_803E3174;
extern f32 lbl_803E3178;
extern f32 lbl_803E317C;
extern f32 lbl_803E3180;
extern f32 sqrtf(f32 x);
extern int getAngle(f32 a, f32 b);
extern void objMove(int obj, f32 x, f32 y, f32 z);
extern void* Obj_GetPlayerObject(void);
extern void* getTrickyObject(void);
extern void Camera_EnableViewYOffset(void);
extern void CameraShake_SetAllMagnitudes(f32 mag);
extern int getCurSeqNo(void);
extern int timerCountDown(int timer);
extern void spawnExplosion(int obj, f32 scale, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
extern void Obj_SmoothTurnAnglesTowardVelocity(int obj, void* vel, int rate, f32 a, f32 b);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
extern void PSVECSubtract(void* a, void* b, void* out);
extern f32 PSVECMag(void* v);
extern void PSVECNormalize(void* src, void* dst);
extern void PSVECScale(void* src, void* dst, f32 scale);
extern void PSVECAdd(void* a, void* b, void* out);

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
        if ((*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->lastHitObject != 0 &&
            ((*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->lastHitObject == (int)
                Obj_GetPlayerObject() ||
                (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->lastHitObject == (int)
                getTrickyObject()))
        {
            int i;
            ((GameObject*)obj)->anim.alpha = 0;
            ((GameObject*)obj)->unkF4 = 0x78;
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
            for (i = 0; i < 0x19; i++)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x715, NULL, 1, -1, &i);
            }
            Sfx_PlayFromObject(obj, 0x279);
        }
        else if ((*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->contactFlags != 0)
        {
            int i;
            ((GameObject*)obj)->anim.alpha = 0;
            ((GameObject*)obj)->unkF4 = 0x78;
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
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
