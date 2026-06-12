#include "main/dll/MMP/MMP_asteroid.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/xyzanimator.h"
#include "main/expgfx.h"
#include "main/game_object.h"

typedef struct PollenfragmentState
{
    u8 pad0[0x4 - 0x0];
    s16 unk4;
    s16 unk6;
    u8 pad8[0x10 - 0x8];
    s16 unk10;
    s16 unk12;
    u8 pad14[0x28 - 0x14];
} PollenfragmentState;


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
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8005fe14();
extern uint FUN_8007f6c8();
extern undefined4 FUN_8007f718();
extern undefined4 FUN_8008112c();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
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
extern void* objCreateLight(int obj, int kind);
extern void modelLightStruct_setLightKind(int light, int value);
extern void modelLightStruct_setPosition(int light, f32 x, f32 y, f32 z);
extern void modelLightStruct_setDiffuseColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setSpecularColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setupGlow(int light, int a, int r, int g, int b, int alpha, f32 radius);
extern void modelLightStruct_setDiffuseTargetColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 near, f32 far);
extern void lightSetField4D(int light, int v);
extern void modelLightStruct_setEnabled(int light, int enabled, f32 scale);
extern void modelLightStruct_startColorFade(int light, int a, int b);
extern f32 lbl_803E30E0;
extern f32 lbl_803E30F8;
extern f32 lbl_803E3108;
extern f32 lbl_803E310C;



#pragma dont_inline on
void fn_8016A660(int obj)
{
    extern u8 Obj_IsLoadingLocked(void);
    extern u8*Obj_AllocObjectSetup(int size, int type);
    extern u8*Obj_SetupObject(u8* obj, int a, int b, int c, int d);
    extern f32 lbl_803E3144;
    extern f32 lbl_803E3148;
    int burstCounter;
    PollenExtra* extra;
    u8* fragment;

    extra = *(PollenExtra**)&((GameObject*)obj)->extra;
    if (Obj_IsLoadingLocked() != 0)
    {
        burstCounter = POLLEN_FRAGMENT_BURST_COUNTER_START;
        do
        {
            fragment = Obj_AllocObjectSetup(POLLEN_FRAGMENT_SETUP_SIZE, POLLEN_FRAGMENT_OBJECT_ID);
            ((GameObject*)fragment)->anim.rootMotionScale = ((GameObject*)obj)->anim.localPosX;
            ((GameObject*)fragment)->anim.localPosX = ((GameObject*)obj)->anim.localPosY;
            ((GameObject*)fragment)->anim.localPosY = ((GameObject*)obj)->anim.localPosZ;
            *(u8*)&((GameObject*)fragment)->anim.rotZ = 1;
            *(u8*)(fragment + 5) = 1;
            *(u8*)&((GameObject*)fragment)->anim.flags = 0xff;
            *(u8*)(fragment + 7) = 0xff;
            fragment = Obj_SetupObject(fragment, POLLEN_FRAGMENT_SETUP_KIND, -1, -1, 0);
            if (fragment != 0)
            {
                ((GameObject*)fragment)->anim.rotY = 0;
                ((GameObject*)fragment)->anim.rotX = (s16)randomGetRange(0, POLLEN_FRAGMENT_RANDOM_ANGLE_MAX);
                ((GameObject*)fragment)->anim.velocityX =
                    lbl_803E3144 *
                    (f32)(s32)
                randomGetRange(POLLEN_FRAGMENT_RANDOM_OFFSET_MIN,
                               POLLEN_FRAGMENT_RANDOM_OFFSET_MAX) +
                    ((GameObject*)obj)->anim.velocityX;
                ((GameObject*)fragment)->anim.velocityY =
                    lbl_803E3148 *
                    (f32)(s32)
                randomGetRange(POLLEN_FRAGMENT_RANDOM_OFFSET_MIN,
                               POLLEN_FRAGMENT_RANDOM_OFFSET_MAX) +
                    ((GameObject*)obj)->anim.velocityY;
                ((GameObject*)fragment)->anim.velocityZ =
                    lbl_803E3144 *
                    (f32)(s32)
                randomGetRange(POLLEN_FRAGMENT_RANDOM_OFFSET_MIN,
                               POLLEN_FRAGMENT_RANDOM_OFFSET_MAX) +
                    ((GameObject*)obj)->anim.velocityZ;
                *(int*)(fragment + POLLEN_FRAGMENT_PARENT_OBJECT_OFFSET) = obj;
            }
        }
        while (burstCounter-- != 0);
        extra->fragmentSpawnTimer = POLLEN_FRAGMENT_SPAWN_TIMER_FRAMES;
    }
}
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
void pollenfragment_init(int obj, int config)
{
    bool keepSpawning;
    s8 pollenType;
    uint randomValue;
    int spawnCount;
    undefined4* state;

    state = *(undefined4**)&((GameObject*)obj)->extra;
    if (*(char*)(config + 0x19) == '\x01')
    {
        *(float*)(state + 2) = lbl_803E3198;
    }
    else
    {
        randomValue = randomGetRange(0xb4, 300);
        *(float*)(state + 2) = (float)(int)randomValue;
    }
    pollenType = *(s8*)(config + 0x19);
    if ((s8)pollenType < 0)
    {
        pollenType = 0;
    }
    else if (pollenType > 5u)
    {
        pollenType = 5;
    }
    *(s8*)(config + 0x19) = pollenType;
    state[7] = (u32)lbl_8032059C[*(char*)(config + 0x19)];
    if ((int)*(short*)state[7] != 0)
    {
        Sfx_PlayFromObjectLimited(obj, (int)*(short*)state[7] & 0xffff, 3);
    }
    spawnCount = 4;
    do
    {
        (*gPartfxInterface)->spawnObject((void*)obj, (int)*(short*)(state[7] + 6),
                                         NULL, 1, -1, NULL);
    }
    while (spawnCount-- != 0);
    if (!((PollenFragmentDef*)state[7])->timed)
    {
        *(float*)(state + 2) = lbl_803E319C;
    }
    ObjHits_SetTargetMask(obj, 4);
    state[6] = 0;
    *(f32*)(state + 1) = *(f32*)(state[7] + 0xc);
    *state = 0;
    s16toFloat(state + 9, 0xe10);
    storeZeroToFloatParam(state + 8);
    return;
}


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

void pollen_release(void)
{
}

void pollen_initialise(void)
{
}

void pollenfragment_release(void)
{
}

void pollenfragment_initialise(void)
{
}

void mikabomb_hitDetect(void);

extern ModgfxInterface** gModgfxInterface;
extern f32 lbl_803E313C;

void pinponspike_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void pollen_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void pinponspike_init(int obj)
{
    ((GameObject*)obj)->unkF4 = 0;
    ObjHits_DisableObject(obj);
    ((GameObject*)obj)->anim.alpha = 0xff;
    Sfx_PlayFromObject(obj, SFXsc_attack02);
    ((GameObject*)obj)->objectFlags |= 0x6000;
}

void pollen_hitDetect(int obj)
{
    ObjHitsPriorityState* hitState = *(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState;
    if (hitState->contactFlags != 0)
    {
        f32 fz;
        ((GameObject*)obj)->anim.localPosX = (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->
            contactPosX;
        ((GameObject*)obj)->anim.localPosY = (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->
            contactPosY;
        ((GameObject*)obj)->anim.localPosZ = (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->
            contactPosZ;
        fz = lbl_803E313C;
        ((GameObject*)obj)->anim.velocityX = fz;
        ((GameObject*)obj)->anim.velocityY = fz;
        ((GameObject*)obj)->anim.velocityZ = fz;
        ((GameObject*)obj)->anim.alpha = 0;
        ObjHits_DisableObject(obj);
    }
}

void pollenfragment_free(int obj)
{
    int* inner = ((GameObject*)obj)->extra;
    if ((void*)inner[6] != NULL)
    {
        ModelLightStruct_free((void*)inner[6]);
        inner[6] = 0;
    }
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void mikabomb_free(int obj, int mode);

/* 8b "li r3, N; blr" returners. */
int pinponspike_getExtraSize(void) { return 0x0; }
int pinponspike_getObjectTypeId(void) { return 0x0; }
int pollen_getExtraSize(void) { return 0x14; }
int pollen_getObjectTypeId(void) { return 0x0; }
int pollenfragment_getExtraSize(void) { return 0x28; }
int pollenfragment_getObjectTypeId(void) { return 0x0; }
int mikabomb_getExtraSize(void);
int mikabomb_getObjectTypeId(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3138;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E31C0;

void pollen_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3138);
}

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

void pollenfragment_render(int* obj, int p2, int p3, int p4, int p5)
{
    int* state = ((GameObject*)obj)->extra;
    if (fn_80080150((int)((char*)state + 0x20)) != 0) return;
    ((void(*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E3158);
}

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

void pollen_init(int* obj)
{
    s16* state = ((GameObject*)obj)->extra;
    state[0] = (s16)randomGetRange(-0x8000, 0x7fff);
    *(f32*)&((XyzAnimatorState*)state)->dataBuffer = lbl_803E3148 * (f32)(s32)
    randomGetRange(0xfa0, 0x1388);
    *(s16*)((char*)state + 4) = (s16)randomGetRange(-0x8000, 0x7fff);
    *(f32*)&((XyzAnimatorState*)state)->unk8 = lbl_803E313C;
    *(s16*)((char*)state + 6) = (s16)randomGetRange(0xe6, 0x1f4);
    *(s16*)((char*)state + 0x10) = 0;
    *(s16*)((char*)state + 0x12) = 0;
    ((GameObject*)obj)->anim.alpha = 0xff;
    ObjHits_DisableObject(obj);
    {
        int* p = *(int**)&((GameObject*)obj)->anim.modelState;
        if (p != NULL)
        {
            *(int*)&((ObjModelState*)p)->flags = *(int*)&((ObjModelState*)p)->flags | 0x810;
        }
    }
}

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

void pollen_update(int obj)
{
    PollenExtra* extra;
    int i;

    extra = *(PollenExtra**)&((GameObject*)obj)->extra;
    if (extra->fragmentSpawnTimer != 0)
    {
        extra->fragmentSpawnTimer -= 1;
    }
    else
    {
        f32 prev = ((GameObject*)obj)->anim.velocityY;
        ((GameObject*)obj)->anim.velocityY = -(lbl_803E3140 * timeDelta - prev);
        if (prev >= lbl_803E313C && ((GameObject*)obj)->anim.velocityY <= lbl_803E313C)
        {
            fn_8016A660(obj);
            Sfx_PlayFromObject(obj, 0xb7);
            ((GameObject*)obj)->anim.alpha = 0;
        }
        objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
                ((GameObject*)obj)->anim.velocityZ * timeDelta);
        ObjHits_SetHitVolumeSlot(obj, 0x16, 1, 0);
        ObjHitbox_SetSphereRadius(obj, 7);
        ObjHits_EnableObject(obj);
        if ((*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->lastHitObject != 0 &&
            ((*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->lastHitObject == (int)
                Obj_GetPlayerObject() ||
                (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->lastHitObject == (int)
                getTrickyObject()))
        {
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E3138);
            Sfx_PlayFromObject(obj, 0xb6);
            ((GameObject*)obj)->anim.alpha = 0;
            extra->fragmentSpawnTimer = 0x3c;
            ObjHits_DisableObject(obj);
        }
        if (((GameObject*)obj)->anim.alpha == 0xff)
        {
            i = 2;
            do
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x4ba, NULL, 1, -1, NULL);
            }
            while (i-- != 0);
        }
    }
    if (((GameObject*)obj)->anim.alpha == 0 && extra->fragmentSpawnTimer == 0)
    {
        Obj_FreeObject(obj);
    }
}

void pollenfragment_hitDetect(int obj)
{
    u8* extra;
    int hit;
    u8 buf[16];

    extra = *(u8**)&((GameObject*)obj)->extra;
    if (fn_80080150((int)(extra + 0x20)) == 0)
    {
        hit = ObjHits_GetPriorityHit(obj, buf, 0, 0);
        if (hit == 0xe || hit == 0xf)
        {
            if ((((PollenFragmentExtra*)extra)->def)->explodeSfx != -1)
            {
                spawnExplosion(obj, lbl_803E315C, 0, 1, 0, 1, 0, 1, 0);
                Sfx_PlayFromObjectLimited(obj, (u16)(((PollenFragmentExtra*)extra)->def)->explodeSfx, 3);
            }
            ObjHits_DisableObject(obj);
            s16toFloat(extra + 0x20, 0x78);
        }
        if ((*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->contactFlags != 0)
        {
            ObjHits_DisableObject(obj);
            *(f32*)(extra + 8) = lbl_803E3160;
            if ((((PollenFragmentExtra*)extra)->def)->explodeSfx != -1)
            {
                spawnExplosion(obj, lbl_803E315C, 0, 1, 0, 1, 0, 1, 0);
                Sfx_PlayFromObjectLimited(obj, (u16)(((PollenFragmentExtra*)extra)->def)->explodeSfx, 3);
            }
            s16toFloat(extra + 0x20, 0x78);
        }
    }
}

void pollenfragment_update(int obj)
{
    u8* extra;
    u8* nearObj;
    void* hit;
    int i;
    f32 w;
    f32 m;
    XyzVec dir;
    XyzVec sc;
    XyzVec pos;

    extra = *(u8**)&((GameObject*)obj)->extra;
    if (getCurSeqNo() != 0)
    {
        Obj_FreeObject(obj);
        return;
    }
    if (fn_80080150((int)extra + 0x20) != 0)
    {
        if (timerCountDown((int)extra + 0x20) != 0)
        {
            Obj_FreeObject(obj);
        }
        return;
    }
    if (timerCountDown((int)extra + 0x24) != 0)
    {
        s16toFloat(extra + 0x20, 0x78);
    }
    if (*(void**)&((GameObject*)obj)->ownerObj != NULL)
    {
        *(int*)extra = *(int*)&((GameObject*)obj)->ownerObj;
        *(int*)&((GameObject*)obj)->ownerObj = 0;
    }
    if ((((PollenFragmentExtra*)extra)->def)->timed)
    {
        *(f32*)(extra + 8) -= timeDelta;
        if (*(f32*)(extra + 8) <= lbl_803E3160)
        {
            if (((GameObject*)obj)->anim.alpha == 0xff)
            {
                i = 2;
                do
                {
                    (*gPartfxInterface)->spawnObject(
                        (void*)obj, (int)(((PollenFragmentExtra*)extra)->def)->burstFx, NULL,
                        1, -1, NULL);
                }
                while (i-- != 0);
            }
            *(f32*)(extra + 8) = lbl_803E3160;
            if (((GameObject*)obj)->anim.alpha >= framesThisStep << 3)
            {
                ((GameObject*)obj)->anim.alpha -= framesThisStep << 3;
            }
            else
            {
                ((GameObject*)obj)->anim.alpha = 0;
                Obj_FreeObject(obj);
                return;
            }
        }
    }
    if ((((PollenFragmentExtra*)extra)->def)->auraFx != -1)
    {
        (*gPartfxInterface)->spawnObject((void*)obj,
                                         (int)(((PollenFragmentExtra*)extra)->def)->auraFx,
                                         NULL, 1, -1, NULL);
    }
    nearObj = (u8*)ObjGroup_FindNearestObject((int)(((PollenFragmentExtra*)extra)->def)->targetGroup, obj, 0);
    if (nearObj != NULL &&
        (!(((PollenFragmentExtra*)extra)->def)->timed || *(f32*)(extra + 8) < lbl_803E3164))
    {
        if ((((PollenFragmentExtra*)extra)->def)->usePath)
        {
            ObjPath_GetPointWorldPosition(nearObj, 0, &pos.x, &pos.y, &pos.z, 0);
        }
        else
        {
            f32 prod;
            pos.x = ((GameObject*)nearObj)->anim.worldPosX;
            prod = ((GameObject*)nearObj)->anim.hitboxScale * ((GameObject*)nearObj)->anim.rootMotionScale;
            pos.y = prod * lbl_803E3168 + ((GameObject*)nearObj)->anim.worldPosY;
            pos.z = ((GameObject*)nearObj)->anim.worldPosZ;
        }
        PSVECSubtract(&pos, (void*)(obj + 0x18), &dir);
        PSVECMag(&dir);
        PSVECNormalize(&dir, &dir);
        PSVECSubtract(&dir, extra + 0xc, &sc);
        ((PollenFragmentExtra*)extra)->velX = dir.x;
        ((PollenFragmentExtra*)extra)->velY = dir.y;
        ((PollenFragmentExtra*)extra)->velZ = dir.z;
        PSVECScale(&sc, &sc, lbl_803E315C);
        PSVECAdd(&dir, &sc, &dir);
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX +
            ((*(f32*)(extra + 8) + (w = lbl_803E315C)) * (dir.x * *(f32*)(extra + 4))) / (m = lbl_803E3164);
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ +
            ((w + *(f32*)(extra + 8)) * (dir.z * *(f32*)(extra + 4))) / m;
        if (!(((PollenFragmentExtra*)extra)->def)->noVertical)
        {
            ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY +
                ((w + *(f32*)(extra + 8)) * (lbl_803E316C * (dir.y * *(f32*)(extra + 4)))) / m;
        }
    }
    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (w = lbl_803E3170);
    ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * w;
    ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * lbl_803E3174;
    if ((((PollenFragmentExtra*)extra)->def)->noVertical)
    {
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY -
            (lbl_803E3178 * timeDelta * *(f32*)(extra + 8)) / lbl_803E317C;
    }
    if ((((PollenFragmentExtra*)extra)->def)->smoothTurn)
    {
        Obj_SmoothTurnAnglesTowardVelocity(obj, (void*)(obj + 0x24), 10, lbl_803E3160, lbl_803E3158);
        ((GameObject*)obj)->anim.rotZ = ((GameObject*)obj)->anim.rotZ + framesThisStep * 0x500;
    }
    else if (((GameObject*)obj)->anim.seqId == 0x482)
    {
        ((GameObject*)obj)->anim.rotX = (s16)(int)(
            lbl_803E3180 * lbl_803DBD48 * (f32)(u32)framesThisStep + (f32)(int)((GameObject*)obj)->anim.rotX);
        ((GameObject*)obj)->anim.rotY = (s16)(int)(
            lbl_803DBD4C * (f32)(u32)framesThisStep + (f32)(int)((GameObject*)obj)->anim.rotY);
    }
    Sfx_KeepAliveLoopedObjectSound(obj, (u16)(((PollenFragmentExtra*)extra)->def)->loopSfx);
    objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
            ((GameObject*)obj)->anim.velocityZ * timeDelta);
    ObjHits_SetHitVolumeSlot(obj, 0x16, 1, 0);
    ObjHits_EnableObject(obj);
    hit = (void*)(*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->lastHitObject;
    if (hit != NULL && *(s16*)((u8*)hit + 0x46) != ((GameObject*)obj)->anim.seqId && hit != *(void**)extra)
    {
        *(f32*)(extra + 8) = lbl_803E3160;
        ObjHits_DisableObject(obj);
        if ((((PollenFragmentExtra*)extra)->def)->explodeSfx != -1)
        {
            spawnExplosion(obj, lbl_803E315C, 0, 1, 0, 1, 0, 1, 0);
            Sfx_PlayFromObjectLimited(obj, (u16)(((PollenFragmentExtra*)extra)->def)->explodeSfx, 3);
        }
        s16toFloat(extra + 0x20, 0x78);
    }
}
