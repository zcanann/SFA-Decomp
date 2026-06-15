#include "main/dll/MMP/MMP_asteroid.h"
#include "main/dll/xyzanimator.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/objhits.h"

extern undefined4 FUN_800067e8();
extern u32 randomGetRange(int min, int max);
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

extern f32 lbl_803E3DF4;
extern f32 lbl_803E3DF8;
extern f32 lbl_803E3198;
extern f32 lbl_803E319C;

extern void objRenderFn_8003b8f4(f32);
extern void kaldachompspit_free(void);
extern void kaldachompspit_update(void);
extern int kaldachompspit_getObjectTypeId(void);
extern int kaldachompspit_getExtraSize(void);
extern int fn_80080150(int p);
extern f32 lbl_803E3158;
extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 lbl_803DBD48;
extern f32 lbl_803DBD4C;
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
extern void objMove(int obj, f32 x, f32 y, f32 z);
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
    pollenType = (pollenType < 0) ? 0 : ((pollenType > 5u) ? 5 : pollenType);
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

void FUN_8016b228(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  uint param_9)
{
    uint uVar1;
    int iVar2;
    int iVar3;
    ObjHitsPriorityState* hitState;
    int hitObject;

    iVar3 = *(int*)&((GameObject*)param_9)->extra;
    hitState = (ObjHitsPriorityState*)((GameObject*)param_9)->anim.hitReactState;
    uVar1 = FUN_8007f6c8((float*)(iVar3 + 0x20));
    if (uVar1 == 0)
    {
        iVar2 = ObjHits_GetPriorityHit(param_9, &hitObject, (int*)0x0, (uint*)0x0);
        if ((iVar2 == 0xe) || (iVar2 == 0xf))
        {
            if (*(short*)(((XyzAnimatorState*)iVar3)->unk1C + 4) != -1)
            {
                FUN_8008112c((double)lbl_803E3DF4, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             param_9, 0, 1, 0, 1, 0, 1, 0);
                FUN_800067e8(param_9, *(ushort*)(((XyzAnimatorState*)iVar3)->unk1C + 4), 3);
            }
            ObjHits_DisableObject((u32)param_9);
            FUN_8007f718((float*)(iVar3 + 0x20), 0x78);
        }
        if (hitState->contactFlags != 0)
        {
            ObjHits_DisableObject((u32)param_9);
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

void pinponspike_render(void);

void pinponspike_hitDetect(void);

void pinponspike_release(void);

void pinponspike_initialise(void);

void pollen_release(void);

void pollen_initialise(void);

void pollenfragment_release(void)
{
}

void pollenfragment_initialise(void)
{
}

void mikabomb_hitDetect(void);

void pinponspike_free(int obj);

void pollen_free(int obj);

void pinponspike_init(int obj);

void pollen_hitDetect(int obj);

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

int pinponspike_getExtraSize(void);
int pinponspike_getObjectTypeId(void);
int pollen_getExtraSize(void);
int pollen_getObjectTypeId(void);
int pollenfragment_getExtraSize(void) { return 0x28; }
int pollenfragment_getObjectTypeId(void) { return 0x0; }
int mikabomb_getExtraSize(void);

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

void pollen_init(int obj);

/* ==== v1.0 recovered functions (drift additions) ==== */

typedef struct
{
    f32 x, y, z;
} XyzVec;

void pinponspike_update(int obj);

void pollen_update(int obj);

void pollenfragment_hitDetect(int obj)
{
    u8* extra;
    int hitType;
    int hitObject;

    extra = *(u8**)&((GameObject*)obj)->extra;
    if (fn_80080150((int)(extra + 0x20)) == 0)
    {
        hitType = ObjHits_GetPriorityHit(obj, &hitObject, 0, 0);
        if (hitType == 0xe || hitType == 0xf)
        {
            if ((((PollenFragmentExtra*)extra)->def)->explodeSfx != -1)
            {
                spawnExplosion(obj, lbl_803E315C, 0, 1, 0, 1, 0, 1, 0);
                Sfx_PlayFromObjectLimited(obj, (u16)(((PollenFragmentExtra*)extra)->def)->explodeSfx, 3);
            }
            ObjHits_DisableObject((u32)obj);
            s16toFloat(extra + 0x20, 0x78);
        }
        if (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->contactFlags != 0)
        {
            ObjHits_DisableObject((u32)obj);
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
    ObjHits_SetHitVolumeSlot((u32)obj, 0x16, 1, 0);
    ObjHits_EnableObject((u32)obj);
    hit = (void*)((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject;
    if (hit != NULL && *(s16*)((u8*)hit + 0x46) != ((GameObject*)obj)->anim.seqId && hit != *(void**)extra)
    {
        *(f32*)(extra + 8) = lbl_803E3160;
        ObjHits_DisableObject((u32)obj);
        if ((((PollenFragmentExtra*)extra)->def)->explodeSfx != -1)
        {
            spawnExplosion(obj, lbl_803E315C, 0, 1, 0, 1, 0, 1, 0);
            Sfx_PlayFromObjectLimited(obj, (u16)(((PollenFragmentExtra*)extra)->def)->explodeSfx, 3);
        }
        s16toFloat(extra + 0x20, 0x78);
    }
}
